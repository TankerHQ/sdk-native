#include <Tanker/Session.hpp>

#include <Tanker/AttachResult.hpp>
#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DeviceKeyStore.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/Encryptor/v4.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Errors/ServerErrc.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Groups/GroupUpdater.hpp>
#include <Tanker/Groups/Manager.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Preregistration.hpp>
#include <Tanker/ReceiveKey.hpp>
#include <Tanker/ResourceKeyStore.hpp>
#include <Tanker/Retry.hpp>
#include <Tanker/Revocation.hpp>
#include <Tanker/Share.hpp>
#include <Tanker/Streams/DecryptionStream.hpp>
#include <Tanker/Streams/PeekableInputSource.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/TrustchainPuller.hpp>
#include <Tanker/TrustchainStore.hpp>
#include <Tanker/Types/Passphrase.hpp>
#include <Tanker/Types/SSecretProvisionalIdentity.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Unlock/Create.hpp>
#include <Tanker/Unlock/Registration.hpp>
#include <Tanker/UserKeyStore.hpp>
#include <Tanker/Utils.hpp>

#include <Tanker/Tracer/ScopeTimer.hpp>

#include <boost/variant2/variant.hpp>
#include <cppcodec/base64_rfc4648.hpp>
#include <cppcodec/base64_url_unpadded.hpp>
#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <tconcurrent/async_wait.hpp>
#include <tconcurrent/future.hpp>
#include <tconcurrent/promise.hpp>
#include <tconcurrent/when.hpp>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/split.hpp>

#include <algorithm>
#include <cassert>
#include <iterator>
#include <stdexcept>
#include <utility>

using Tanker::Trustchain::GroupId;
using Tanker::Trustchain::ResourceId;
using Tanker::Trustchain::UserId;
using namespace Tanker::Trustchain::Actions;
using namespace Tanker::Errors;

TLOG_CATEGORY(Session);

namespace Tanker
{
namespace
{
void matchProvisional(
    Unlock::Verification const& verification,
    Identity::SecretProvisionalIdentity const& provisionalIdentity)
{
  namespace bv = boost::variant2;
  namespace ba = boost::algorithm;

  if (!(bv::holds_alternative<Unlock::EmailVerification>(verification) ||
        bv::holds_alternative<OidcIdToken>(verification)))
    throw Exception(make_error_code(Errc::InvalidArgument),
                    "unknown verification method for provisional identity");

  if (auto const emailVerification =
          bv::get_if<Unlock::EmailVerification>(&verification))
  {
    if (emailVerification->email != Email{provisionalIdentity.value})
      throw Exception(make_error_code(Errc::InvalidArgument),
                      "verification email does not match provisional identity");
  }
  else if (auto const oidcIdToken = bv::get_if<OidcIdToken>(&verification))
  {
    std::string jwtEmail;
    try
    {
      std::vector<std::string> res;
      ba::split(res, *oidcIdToken, ba::is_any_of("."));
      jwtEmail = nlohmann::json::parse(
                     cppcodec::base64_url_unpadded::decode(res.at(1)))
                     .at("email");
    }
    catch (...)
    {
      throw Exception(make_error_code(Errc::InvalidArgument),
                      "Failed to parse verification oidcIdToken");
    }
    if (jwtEmail != provisionalIdentity.value)
      throw Exception(make_error_code(Errc::InvalidArgument),
                      "verification does not match provisional identity");
  }
}
}

Session::Session(Config&& config)
  : _trustchainId(config.trustchainId),
    _userId(config.userId),
    _userSecret(config.userSecret),
    _db(std::move(config.db)),
    _deviceKeyStore(std::move(config.deviceKeyStore)),
    _client(std::move(config.client)),
    _trustchain(_db.get()),
    _userKeyStore(_db.get()),
    _contactStore(_db.get()),
    _groupStore(_db.get()),
    _resourceKeyStore(_db.get()),
    _provisionalUserKeysStore(_db.get()),
    _verifier(_trustchainId, _db.get(), &_contactStore, &_groupStore),
    _trustchainPuller(&_trustchain,
                      &_verifier,
                      _db.get(),
                      &_contactStore,
                      &_userKeyStore,
                      &*_deviceKeyStore,
                      _client.get(),
                      _deviceKeyStore->signatureKeyPair().publicKey,
                      _deviceKeyStore->deviceId(),
                      _userId),
    _userAccessor(_userId, _client.get(), &_trustchainPuller, &_contactStore),
    _groupAcessor(&_trustchainPuller, &_groupStore),
    _resourceKeyAccessor(_client.get(),
                         &_verifier,
                         &_userKeyStore,
                         &_groupAcessor,
                         &_provisionalUserKeysStore,
                         &_resourceKeyStore),
    _blockGenerator(_trustchainId,
                    _deviceKeyStore->signatureKeyPair().privateKey,
                    _deviceKeyStore->deviceId())
{
  _client->setConnectionHandler(
      [this]() -> tc::cotask<void> { TC_AWAIT(connectionHandler()); });

  _client->blockAvailable = [this] { _trustchainPuller.scheduleCatchUp(); };

  _trustchainPuller.receivedThisDeviceId =
      [this](auto const& deviceId) -> tc::cotask<void> {
    TC_AWAIT(this->setDeviceId(deviceId));
  };
  _trustchainPuller.receivedKeyToDevice =
      [this](auto const& entry) -> tc::cotask<void> {
    TC_AWAIT(this->onKeyToDeviceReceived(entry));
  };
  _trustchainPuller.deviceCreated =
      [this](auto const& entry) -> tc::cotask<void> {
    TC_AWAIT(onDeviceCreated(entry));
  };
  _trustchainPuller.userGroupActionReceived =
      [this](auto const& entry) -> tc::cotask<void> {
    TC_AWAIT(onUserGroupEntry(entry));
  };
  _trustchainPuller.provisionalIdentityClaimReceived =
      [this](auto const& entry) -> tc::cotask<void> {
    TC_AWAIT(onProvisionalIdentityClaimEntry(entry));
  };
  _trustchainPuller.trustchainCreationReceived =
      [this](auto const& entry) -> tc::cotask<void> {
    TC_AWAIT(onTrustchainCreationReceived(entry));
  };
  _trustchainPuller.deviceRevoked =
      [this](auto const& entry) -> tc::cotask<void> {
    TC_AWAIT(onDeviceRevoked(entry));
  };
}

tc::cotask<void> Session::connectionHandler()
{
  // NOTE: It is MANDATORY to check this prefix is valid, or the server could
  // get us to sign anything!
  static std::string const challengePrefix =
      u8"\U0001F512 Auth Challenge. 1234567890.";
  try
  {
    auto const challenge = TC_AWAIT(_client->requestAuthChallenge());
    if (!boost::algorithm::starts_with(challenge, challengePrefix))
    {
      throw formatEx(
          Errc::InternalError,
          "received auth challenge does not contain mandatory prefix, server "
          "may not be up to date, or we may be under attack.");
    }
    auto const signature =
        Crypto::sign(gsl::make_span(challenge).as_span<uint8_t const>(),
                     _deviceKeyStore->signatureKeyPair().privateKey);
    auto const request = nlohmann::json{
        {"signature", signature},
        {"public_signature_key", _deviceKeyStore->signatureKeyPair().publicKey},
        {"trustchain_id", _trustchainId},
        {"user_id", _userId}};
    TC_AWAIT(_client->authenticateDevice(request));
  }
  catch (std::exception const& e)
  {
    TERROR("Failed to authenticate session: {}", e.what());
  }
}

tc::cotask<void> Session::startConnection()
{
  FUNC_TIMER(Net);
  auto const deviceId = _deviceKeyStore->deviceId();
  if (!deviceId.is_null() && gotDeviceId)
    gotDeviceId(deviceId);

  TC_AWAIT(_client->handleConnection());

  _taskCanceler.add(tc::async_resumable([this]() -> tc::cotask<void> {
    try
    {
      TC_AWAIT(syncTrustchain());
      if (!_ready.get_future().is_ready())
        _ready.set_value({});
    }
    catch (...)
    {
      if (!_ready.get_future().is_ready())
        _ready.set_exception(std::current_exception());
      throw;
    }
  }));

  if (_deviceKeyStore->deviceId().is_null())
  {
    SCOPE_TIMER("wait for trustchain sync", Net);
    TC_AWAIT(_ready.get_future());
  }
}

UserId const& Session::userId() const
{
  return this->_userId;
}

Trustchain::TrustchainId const& Session::trustchainId() const
{
  return this->_trustchainId;
}

Crypto::SymmetricKey const& Session::userSecret() const
{
  return this->_userSecret;
}

tc::cotask<void> Session::encrypt(
    uint8_t* encryptedData,
    gsl::span<uint8_t const> clearData,
    std::vector<SPublicIdentity> const& spublicIdentities,
    std::vector<SGroupId> const& sgroupIds)
{
  auto const metadata = TC_AWAIT(Encryptor::encrypt(encryptedData, clearData));
  auto spublicIdentitiesWithUs = spublicIdentities;
  spublicIdentitiesWithUs.push_back(SPublicIdentity{
      to_string(Identity::PublicPermanentIdentity{_trustchainId, _userId})});

  TC_AWAIT(_resourceKeyStore.putKey(metadata.resourceId, metadata.key));
  TC_AWAIT(Share::share(_userAccessor,
                        _groupAcessor,
                        _blockGenerator,
                        *_client,
                        {{metadata.key, metadata.resourceId}},
                        spublicIdentitiesWithUs,
                        sgroupIds));
}

tc::cotask<std::vector<uint8_t>> Session::encrypt(
    gsl::span<uint8_t const> clearData,
    std::vector<SPublicIdentity> const& spublicIdentities,
    std::vector<SGroupId> const& sgroupIds)
{
  std::vector<uint8_t> encryptedData(
      Encryptor::encryptedSize(clearData.size()));
  TC_AWAIT(
      encrypt(encryptedData.data(), clearData, spublicIdentities, sgroupIds));
  TC_RETURN(std::move(encryptedData));
}
tc::cotask<void> Session::decrypt(uint8_t* decryptedData,
                                  gsl::span<uint8_t const> encryptedData)
{
  auto const resourceId = Encryptor::extractResourceId(encryptedData);

  auto const key = TC_AWAIT(getResourceKey(resourceId));

  TC_AWAIT(Encryptor::decrypt(decryptedData, key, encryptedData));
}

tc::cotask<std::vector<uint8_t>> Session::decrypt(
    gsl::span<uint8_t const> encryptedData)
{
  std::vector<uint8_t> decryptedData(Encryptor::decryptedSize(encryptedData));
  TC_AWAIT(decrypt(decryptedData.data(), encryptedData));

  TC_RETURN(std::move(decryptedData));
}

tc::cotask<void> Session::setDeviceId(Trustchain::DeviceId const& deviceId)
{
  TC_AWAIT(_deviceKeyStore->setDeviceId(deviceId));
  _trustchainPuller.setDeviceId(deviceId);
  _blockGenerator.setDeviceId(deviceId);
  if (gotDeviceId)
    gotDeviceId(deviceId);
}

Trustchain::DeviceId const& Session::deviceId() const
{
  return _deviceKeyStore->deviceId();
}

tc::cotask<std::vector<Device>> Session::getDeviceList() const
{
  TC_RETURN(TC_AWAIT(_contactStore.findUserDevices(_userId)));
}

tc::cotask<void> Session::share(
    std::vector<SResourceId> const& sresourceIds,
    std::vector<SPublicIdentity> const& spublicIdentities,
    std::vector<SGroupId> const& sgroupIds)
{
  if (spublicIdentities.empty() && sgroupIds.empty())
    TC_RETURN();

  auto resourceIds = convertList(sresourceIds, [](auto&& resourceId) {
    return base64DecodeArgument<ResourceId>(resourceId);
  });

  TC_AWAIT(Share::share(_resourceKeyStore,
                        _userAccessor,
                        _groupAcessor,
                        _blockGenerator,
                        *_client,
                        resourceIds,
                        spublicIdentities,
                        sgroupIds));
}

tc::cotask<SGroupId> Session::createGroup(
    std::vector<SPublicIdentity> const& spublicIdentities)
{
  auto const groupId = TC_AWAIT(Groups::Manager::create(
      _userAccessor, _blockGenerator, *_client, spublicIdentities));
  // Make sure group's lastBlockHash updates before the next group operation
  TC_AWAIT(syncTrustchain());
  TC_RETURN(groupId);
}

tc::cotask<void> Session::updateGroupMembers(
    SGroupId const& groupIdString,
    std::vector<SPublicIdentity> const& spublicIdentitiesToAdd)
{
  auto const groupId = base64DecodeArgument<GroupId>(groupIdString);

  TC_AWAIT(Groups::Manager::updateMembers(_userAccessor,
                                          _blockGenerator,
                                          *_client,
                                          _groupStore,
                                          groupId,
                                          spublicIdentitiesToAdd));

  // Make sure group's lastBlockHash updates before the next group operation
  TC_AWAIT(syncTrustchain());
}

tc::cotask<void> Session::setVerificationMethod(
    Unlock::Verification const& method)
{
  if (boost::variant2::holds_alternative<VerificationKey>(method))
  {
    throw formatEx(Errc::InvalidArgument,
                   "cannot call setVerificationMethod with a verification key");
  }
  else
  {
    try
    {
      TC_AWAIT(_client->setVerificationMethod(
          trustchainId(), userId(), method, userSecret()));
    }
    catch (Errors::Exception const& e)
    {
      if (e.errorCode() == ServerErrc::VerificationKeyNotFound)
      {
        // the server does not send an error message
        throw Errors::Exception(make_error_code(Errc::PreconditionFailed),
                                "cannot call setVerificationMethod after a "
                                "verification key has been used");
      }
      throw;
    }
  }
}

tc::cotask<std::vector<Unlock::VerificationMethod>>
Session::fetchVerificationMethods()
{
  TC_RETURN(TC_AWAIT(
      _client->fetchVerificationMethods(_trustchainId, _userId, _userSecret)));
}

tc::cotask<AttachResult> Session::attachProvisionalIdentity(
    SSecretProvisionalIdentity const& sidentity)
{
  auto const provisionalIdentity =
      Identity::extract<Identity::SecretProvisionalIdentity>(
          sidentity.string());
  if (provisionalIdentity.target != Identity::TargetType::Email)
  {
    throw AssertionError(
        fmt::format(TFMT("unsupported provisional identity target {:s}"),
                    provisionalIdentity.target));
  }
  if (TC_AWAIT(_provisionalUserKeysStore
                   .findProvisionalUserKeysByAppPublicEncryptionKey(
                       provisionalIdentity.appEncryptionKeyPair.publicKey)))
  {
    TC_RETURN((AttachResult{Tanker::Status::Ready, nonstd::nullopt}));
  }
  auto const email = Email{provisionalIdentity.value};
  try
  {
    auto const tankerKeys = TC_AWAIT(
        this->_client->getVerifiedProvisionalIdentityKeys(Crypto::generichash(
            gsl::make_span(email).as_span<std::uint8_t const>())));
    if (tankerKeys)
    {
      auto block = _blockGenerator.provisionalIdentityClaim(
          _userId,
          SecretProvisionalUser{provisionalIdentity.target,
                                provisionalIdentity.value,
                                provisionalIdentity.appEncryptionKeyPair,
                                tankerKeys->encryptionKeyPair,
                                provisionalIdentity.appSignatureKeyPair,
                                tankerKeys->signatureKeyPair},
          TC_AWAIT(this->_userKeyStore.getLastKeyPair()));
      TC_AWAIT(_client->pushBlock(block));
      TC_AWAIT(syncTrustchain());
    }
    TC_RETURN((AttachResult{Tanker::Status::Ready, nonstd::nullopt}));
  }
  catch (Tanker::Errors::Exception const& e)
  {
    if (e.errorCode() == ServerErrc::VerificationNeeded)
    {
      _provisionalIdentity = provisionalIdentity;
      TC_RETURN(
          (AttachResult{Tanker::Status::IdentityVerificationNeeded, email}));
    }
    throw;
  }
  throw AssertionError("unreachable code");
}

tc::cotask<void> Session::verifyProvisionalIdentity(
    Unlock::Verification const& verification)
{
  if (!_provisionalIdentity.has_value())
    throw formatEx(
        Errc::PreconditionFailed,
        "cannot call verifyProvisionalIdentity without having called "
        "attachProvisionalIdentity before");
  matchProvisional(verification, _provisionalIdentity.value());
  auto const tankerKeys = TC_AWAIT(
      this->_client->getProvisionalIdentityKeys(verification, _userSecret));
  if (!tankerKeys)
  {
    TINFO("Nothing to claim");
    TC_RETURN();
  }
  auto block = _blockGenerator.provisionalIdentityClaim(
      _userId,
      SecretProvisionalUser{_provisionalIdentity->target,
                            _provisionalIdentity->value,
                            _provisionalIdentity->appEncryptionKeyPair,
                            tankerKeys->encryptionKeyPair,
                            _provisionalIdentity->appSignatureKeyPair,
                            tankerKeys->signatureKeyPair},
      TC_AWAIT(this->_userKeyStore.getLastKeyPair()));
  TC_AWAIT(_client->pushBlock(block));
  _provisionalIdentity.reset();
  TC_AWAIT(syncTrustchain());
}

tc::cotask<void> Session::catchUserKey(
    Trustchain::DeviceId const& deviceId,
    Trustchain::Actions::DeviceCreation const& deviceCreation)

{
  using Trustchain::Actions::DeviceCreation;
  // no new user key (or old device < 3), no need to continue
  if (auto const dc3 = deviceCreation.get_if<DeviceCreation::v3>())
  {
    // you need this so that Share shares to self using the user key
    TC_AWAIT(_contactStore.putUserKey(deviceCreation.userId(),
                                      dc3->publicUserEncryptionKey()));
  }
}

tc::cotask<void> Session::onKeyToDeviceReceived(Entry const& entry)
{
  TC_AWAIT(ReceiveKey::onKeyToDeviceReceived(
      _contactStore,
      _resourceKeyStore,
      _deviceKeyStore->encryptionKeyPair().privateKey,
      entry));
}

tc::cotask<void> Session::onDeviceCreated(Entry const& entry)
{
  auto const& deviceCreation = entry.action.get<DeviceCreation>();
  Trustchain::DeviceId const deviceId{entry.hash};
  TC_AWAIT(catchUserKey(deviceId, deviceCreation));
  Device createdDevice{deviceId,
                       entry.index,
                       nonstd::nullopt,
                       deviceCreation.publicSignatureKey(),
                       deviceCreation.publicEncryptionKey(),
                       deviceCreation.isGhostDevice()};
  TC_AWAIT(_contactStore.putUserDevice(deviceCreation.userId(), createdDevice));
}

tc::cotask<void> Session::onDeviceRevoked(Entry const& entry)
{
  auto const& deviceRevocation = entry.action.get<DeviceRevocation>();

  if (deviceRevocation.deviceId() == this->deviceId())
  {
    TINFO("This device has been revoked");
    if (!_ready.get_future().is_ready())
    {
      _ready.set_exception(std::make_exception_ptr(
          Exception(make_error_code(Errc::OperationCanceled),
                    "this device was revoked")));
    }
    TC_AWAIT(nukeDatabase());
    if (deviceRevoked)
      deviceRevoked();
    TC_RETURN();
  }

  TC_AWAIT(Revocation::onOtherDeviceRevocation(deviceRevocation,
                                               entry,
                                               _userId,
                                               deviceId(),
                                               _contactStore,
                                               _deviceKeyStore,
                                               _userKeyStore));
}

tc::cotask<void> Session::onUserGroupEntry(Entry const& entry)
{
  TC_AWAIT(GroupUpdater::applyEntry(
      _userId, _groupStore, _userKeyStore, _provisionalUserKeysStore, entry));
}

tc::cotask<void> Session::onProvisionalIdentityClaimEntry(Entry const& entry)
{
  TC_AWAIT(Preregistration::applyEntry(
      _userKeyStore, _provisionalUserKeysStore, _groupStore, entry));
}

tc::cotask<void> Session::onTrustchainCreationReceived(Entry const& entry)
{
  TC_AWAIT(_trustchain.setPublicSignatureKey(
      entry.action.get<TrustchainCreation>().publicSignatureKey()));
}

tc::cotask<void> Session::syncTrustchain()
{
  TC_AWAIT(_trustchainPuller.scheduleCatchUp());
}

tc::cotask<void> Session::revokeDevice(Trustchain::DeviceId const& deviceId)
{
  TC_AWAIT(syncTrustchain());
  TC_AWAIT(Revocation::revokeDevice(deviceId,
                                    _userId,
                                    _contactStore,
                                    _userKeyStore,
                                    _blockGenerator,
                                    _client));
}

tc::cotask<void> Session::nukeDatabase()
{
  TC_AWAIT(_db->nuke());
}

tc::cotask<Streams::EncryptionStream> Session::makeEncryptionStream(
    Streams::InputSource cb,
    std::vector<SPublicIdentity> const& spublicIdentities,
    std::vector<SGroupId> const& sgroupIds)
{
  Streams::EncryptionStream encryptor(std::move(cb));

  auto spublicIdentitiesWithUs = spublicIdentities;
  spublicIdentitiesWithUs.push_back(SPublicIdentity{
      to_string(Identity::PublicPermanentIdentity{_trustchainId, _userId})});

  TC_AWAIT(_resourceKeyStore.putKey(encryptor.resourceId(),
                                    encryptor.symmetricKey()));
  TC_AWAIT(Share::share(_userAccessor,
                        _groupAcessor,
                        _blockGenerator,
                        *_client,
                        {{encryptor.symmetricKey(), encryptor.resourceId()}},
                        spublicIdentitiesWithUs,
                        sgroupIds));

  TC_RETURN(std::move(encryptor));
}

tc::cotask<Crypto::SymmetricKey> Session::getResourceKey(
    Trustchain::ResourceId const& resourceId)
{

  auto const key = TC_AWAIT(_resourceKeyAccessor.findKey(resourceId));
  if (!key)
  {
    throw formatEx(
        Errc::InvalidArgument, "key not found for resource: {:s}", resourceId);
  }
  TC_RETURN(*key);
}

tc::cotask<Streams::DecryptionStreamAdapter> Session::makeDecryptionStream(
    Streams::InputSource cb)
{
  auto peekableSource = Streams::PeekableInputSource(std::move(cb));
  auto const version = TC_AWAIT(peekableSource.peek(1));
  if (version.empty())
    throw formatEx(Errc::InvalidArgument, "empty stream");

  if (version[0] == 4)
  {
    auto resourceKeyFinder = [this](Trustchain::ResourceId const& resourceId)
        -> tc::cotask<Crypto::SymmetricKey> {
      TC_RETURN(TC_AWAIT(this->getResourceKey(resourceId)));
    };

    auto streamDecryptor = TC_AWAIT(Streams::DecryptionStream::create(
        std::move(peekableSource), std::move(resourceKeyFinder)));
    TC_RETURN(Streams::DecryptionStreamAdapter(std::move(streamDecryptor),
                                               streamDecryptor.resourceId()));
  }
  else
  {
    auto encryptedData =
        TC_AWAIT(Streams::readAllStream(std::move(peekableSource)));
    auto const resourceId = Encryptor::extractResourceId(encryptedData);
    TC_RETURN(Streams::DecryptionStreamAdapter(
        Streams::bufferToInputSource(TC_AWAIT(decrypt(encryptedData))),
        resourceId));
  }
  throw AssertionError("makeDecryptionStream: unreachable code");
}
}
