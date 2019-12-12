#include <Tanker/Session.hpp>

#include <Tanker/AttachResult.hpp>
#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/Encryptor/v4.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Errors/ServerErrc.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Groups/Manager.hpp>
#include <Tanker/Groups/Requester.hpp>
#include <Tanker/Groups/Updater.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>
#include <Tanker/Log/Log.hpp>
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
#include <Tanker/Unlock/Registration.hpp>
#include <Tanker/Utils.hpp>

#include <Tanker/Tracer/ScopeTimer.hpp>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/variant2/variant.hpp>
#include <cppcodec/base64_rfc4648.hpp>
#include <cppcodec/base64_url_unpadded.hpp>
#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <tconcurrent/async_wait.hpp>
#include <tconcurrent/future.hpp>
#include <tconcurrent/promise.hpp>
#include <tconcurrent/when.hpp>

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
Session::Session(Config&& config)
  : _trustchainId(config.trustchainId),
    _db(std::move(config.db)),
    _localUser(std::move(config.localUser)),
    _client(std::move(config.client)),
    _requester(std::make_unique<Groups::Requester>(_client.get())),
    _trustchain(_db.get()),
    _contactStore(_db.get()),
    _groupStore(_db.get()),
    _resourceKeyStore(_db.get()),
    _provisionalUserKeysStore(_db.get()),
    _verifier(_trustchainId, _localUser.get(), &_contactStore),
    _trustchainPuller(&_trustchain,
                      &_verifier,
                      _db.get(),
                      _localUser.get(),
                      &_contactStore,
                      _client.get()),
    _userAccessor(userId(), _client.get(), &_trustchainPuller, &_contactStore),
    _provisionalUsersAccessor(_client.get(),
                              &_contactStore,
                              _localUser.get(),
                              &_provisionalUserKeysStore),
    _provisionalUsersManager(_localUser.get(),
                             _client.get(),
                             &_provisionalUsersAccessor,
                             &_provisionalUserKeysStore,
                             &_blockGenerator),
    _groupAccessor(_requester.get(),
                   &_trustchainPuller,
                   &_contactStore,
                   &_groupStore,
                   _localUser.get(),
                   &_provisionalUsersAccessor),
    _resourceKeyAccessor(_client.get(),
                         &_verifier,
                         _localUser.get(),
                         &_groupAccessor,
                         &_provisionalUsersAccessor,
                         &_resourceKeyStore),
    _blockGenerator(_trustchainId,
                    _localUser->deviceKeys().signatureKeyPair.privateKey,
                    deviceId())
{
  _client->setConnectionHandler(
      [this]() -> tc::cotask<void> { TC_AWAIT(authenticate()); });

  _client->blockAvailable = [this] { _trustchainPuller.scheduleCatchUp(); };

  _trustchainPuller.receivedThisDeviceId =
      [this](auto const& deviceId) -> tc::cotask<void> {
    TC_AWAIT(this->setDeviceId(deviceId));
  };
  _trustchainPuller.deviceCreated =
      [this](auto const& entry) -> tc::cotask<void> {
    TC_AWAIT(onDeviceCreated(entry));
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

tc::cotask<void> Session::authenticate()
{
  FUNC_TIMER(Net);
  try
  {
    auto const challenge = TC_AWAIT(_client->requestAuthChallenge());
    // NOTE: It is MANDATORY to check this prefix is valid, or the server could
    // get us to sign anything!
    if (!boost::algorithm::starts_with(
            challenge, u8"\U0001F512 Auth Challenge. 1234567890."))
    {
      throw formatEx(
          Errc::InternalError,
          "received auth challenge does not contain mandatory prefix, server "
          "may not be up to date, or we may be under attack.");
    }
    auto const signature =
        Crypto::sign(gsl::make_span(challenge).as_span<uint8_t const>(),
                     _localUser->deviceKeys().signatureKeyPair.privateKey);
    auto const request =
        nlohmann::json{{"signature", signature},
                       {"public_signature_key",
                        _localUser->deviceKeys().signatureKeyPair.publicKey},
                       {"trustchain_id", _trustchainId},
                       {"user_id", userId()}};
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

  if (this->deviceId().is_null())
  {
    SCOPE_TIMER("wait for trustchain sync", Net);
    TC_AWAIT(_ready.get_future());
  }
}

UserId const& Session::userId() const
{
  return this->_localUser->userId();
}

Trustchain::TrustchainId const& Session::trustchainId() const
{
  return this->_trustchainId;
}

Crypto::SymmetricKey const& Session::userSecret() const
{
  return this->_localUser->userSecret();
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
      to_string(Identity::PublicPermanentIdentity{_trustchainId, userId()})});

  TC_AWAIT(_resourceKeyStore.putKey(metadata.resourceId, metadata.key));
  TC_AWAIT(Share::share(_userAccessor,
                        _groupAccessor,
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
  _blockGenerator.setDeviceId(deviceId);
}

Trustchain::DeviceId const& Session::deviceId() const
{
  return _localUser->deviceId();
}

tc::cotask<std::vector<Users::Device>> Session::getDeviceList() const
{
  TC_RETURN(TC_AWAIT(_contactStore.findUserDevices(userId())));
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
                        _groupAccessor,
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
                                          _groupAccessor,
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
  TC_RETURN(TC_AWAIT(_client->fetchVerificationMethods(
      _trustchainId, userId(), userSecret())));
}

tc::cotask<AttachResult> Session::attachProvisionalIdentity(
    SSecretProvisionalIdentity const& sidentity)
{
  TC_RETURN(TC_AWAIT(_provisionalUsersManager.attachProvisionalIdentity(
      TC_AWAIT(_localUser->currentKeyPair()), sidentity)));
}

tc::cotask<void> Session::verifyProvisionalIdentity(
    Unlock::Verification const& verification)
{
  TC_AWAIT(_provisionalUsersManager.verifyProvisionalIdentity(
      TC_AWAIT(_localUser->currentKeyPair()), verification));
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

tc::cotask<void> Session::onDeviceCreated(Entry const& entry)
{
  auto const& deviceCreation = entry.action.get<DeviceCreation>();
  Trustchain::DeviceId const deviceId{entry.hash};
  TC_AWAIT(catchUserKey(deviceId, deviceCreation));
  Users::Device const createdDevice{deviceId,
                                    deviceCreation.userId(),
                                    entry.index,
                                    std::nullopt,
                                    deviceCreation.publicSignatureKey(),
                                    deviceCreation.publicEncryptionKey(),
                                    deviceCreation.isGhostDevice()};
  TC_AWAIT(_contactStore.putUserDevice(createdDevice));
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

  TC_AWAIT(Revocation::onOtherDeviceRevocation(
      deviceRevocation, entry, _contactStore, *_localUser));
}

tc::cotask<void> Session::onTrustchainCreationReceived(Entry const& entry)
{
  TC_AWAIT(_localUser->setTrustchainPublicSignatureKey(
      entry.action.get<TrustchainCreation>().publicSignatureKey()));
}

tc::cotask<void> Session::syncTrustchain()
{
  TC_AWAIT(_trustchainPuller.scheduleCatchUp());
}

tc::cotask<void> Session::revokeDevice(Trustchain::DeviceId const& deviceId)
{
  TC_AWAIT(syncTrustchain());
  TC_AWAIT(Revocation::revokeDevice(
      deviceId, *_localUser, _contactStore, _blockGenerator, _client));
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
      to_string(Identity::PublicPermanentIdentity{_trustchainId, userId()})});

  TC_AWAIT(_resourceKeyStore.putKey(encryptor.resourceId(),
                                    encryptor.symmetricKey()));
  TC_AWAIT(Share::share(_userAccessor,
                        _groupAccessor,
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
