#include <Tanker/Session.hpp>

#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DeviceKeyStore.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Groups/GroupUpdater.hpp>
#include <Tanker/Groups/Manager.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/Preregistration.hpp>
#include <Tanker/ReceiveKey.hpp>
#include <Tanker/RecipientNotFound.hpp>
#include <Tanker/ResourceKeyNotFound.hpp>
#include <Tanker/ResourceKeyStore.hpp>
#include <Tanker/Revocation.hpp>
#include <Tanker/Share.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/TrustchainPuller.hpp>
#include <Tanker/TrustchainStore.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/SSecretProvisionalIdentity.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Unlock/Create.hpp>
#include <Tanker/Unlock/Messages.hpp>
#include <Tanker/Unlock/Registration.hpp>
#include <Tanker/UserKeyStore.hpp>
#include <Tanker/UserNotFound.hpp>
#include <Tanker/Utils.hpp>

#include <Tanker/Tracer/ScopeTimer.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>
#include <tconcurrent/async_wait.hpp>
#include <tconcurrent/future.hpp>
#include <tconcurrent/promise.hpp>
#include <tconcurrent/when.hpp>

#include <boost/algorithm/string/predicate.hpp>

#include <algorithm>
#include <cassert>
#include <iterator>
#include <stdexcept>
#include <utility>

using Tanker::Trustchain::GroupId;
using Tanker::Trustchain::ResourceId;
using Tanker::Trustchain::UserId;
using namespace Tanker::Trustchain::Actions;

TLOG_CATEGORY(Session);

namespace Tanker
{
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
    _keyPublishStore(_db.get()),
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
  _trustchainPuller.keyPublishReceived =
      [this](auto const& entry) -> tc::cotask<void> {
    TC_AWAIT(onKeyPublishReceived(entry));
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
      throw std::runtime_error(
          "Received auth challenge does not contain mandatory prefix. Server "
          "may not be up to date, or we may be under attack.");
    auto const signature =
        Crypto::sign(gsl::make_span(challenge).as_span<uint8_t const>(),
                     _deviceKeyStore->signatureKeyPair().privateKey);
    auto const request = nlohmann::json{
        {"signature", signature},
        {"public_signature_key", _deviceKeyStore->signatureKeyPair().publicKey},
        {"trustchain_id", _trustchainId},
        {"user_id", _userId}};
    _unlockMethods = TC_AWAIT(_client->authenticateDevice(request));
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
    TC_AWAIT(syncTrustchain());
    if (!_ready.get_future().is_ready())
    {
      _ready.set_value({});
    }
  }));

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
  auto const metadata = Encryptor::encrypt(encryptedData, clearData);
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

tc::cotask<void> Session::decrypt(uint8_t* decryptedData,
                                  gsl::span<uint8_t const> encryptedData)
{
  auto const resourceId = Encryptor::extractResourceId(encryptedData);

  // Try to get the key, in order:
  // - from the resource key store
  // - from the trustchain
  // - from the tanker server
  // In all cases, we put the key in the resource key store
  auto key = TC_AWAIT(_resourceKeyStore.findKey(resourceId));
  if (!key)
  {
    auto keyPublish = TC_AWAIT(_keyPublishStore.find(resourceId));
    if (!keyPublish)
    {
      TC_AWAIT(_trustchainPuller.scheduleCatchUp());
      keyPublish = TC_AWAIT(_keyPublishStore.find(resourceId));
    }
    if (keyPublish) // do not use else!
    {
      TC_AWAIT(ReceiveKey::decryptAndStoreKey(_resourceKeyStore,
                                              _userKeyStore,
                                              _groupStore,
                                              _provisionalUserKeysStore,
                                              *keyPublish));
      key = TC_AWAIT(_resourceKeyStore.findKey(resourceId));
    }
  }
  if (!key)
    throw Error::ResourceKeyNotFound(resourceId);

  Encryptor::decrypt(decryptedData, *key, encryptedData);
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
    return cppcodec::base64_rfc4648::decode<ResourceId>(resourceId);
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
  auto const groupId = cppcodec::base64_rfc4648::decode<GroupId>(groupIdString);

  TC_AWAIT(Groups::Manager::updateMembers(_userAccessor,
                                          _blockGenerator,
                                          *_client,
                                          _groupStore,
                                          groupId,
                                          spublicIdentitiesToAdd));

  // Make sure group's lastBlockHash updates before the next group operation
  TC_AWAIT(syncTrustchain());
}

tc::cotask<std::unique_ptr<Unlock::Registration>>
Session::generateVerificationKey()
{
  TC_RETURN(Unlock::generate(
      _userId, TC_AWAIT(_userKeyStore.getLastKeyPair()), _blockGenerator));
}

tc::cotask<void> Session::registerVerificationKey(
    Unlock::Registration const& registration)
{
  TC_AWAIT(_client->pushBlock(registration.block));
}

tc::cotask<void> Session::createVerificationKey()
{
  auto const reg = TC_AWAIT(generateVerificationKey());

  auto const msg =
      Unlock::Message(trustchainId(),
                      deviceId(),
                      Unlock::Verification{reg->verificationKey},
                      userSecret(),
                      _deviceKeyStore->signatureKeyPair().privateKey);
  try
  {
    TC_AWAIT(_client->pushBlock(reg->block));
    TC_AWAIT(_client->createVerificationKey(msg));
  }
  catch (Error::ServerError const& e)
  {
    if (e.httpStatusCode() == 500)
      throw Error::InternalError(e.what());
    else if (e.httpStatusCode() == 409)
      throw Error::VerificationKeyAlreadyExists(
          "A verification key has already been registered");
    else
      throw;
  }
}

void Session::updateLocalUnlockMethods(Unlock::Verification const& method)
{
  if (mpark::holds_alternative<Unlock::EmailVerification>(method))
    _unlockMethods |= Unlock::Method::Email;
  if (mpark::holds_alternative<Password>(method))
    _unlockMethods |= Unlock::Method::Password;
}

tc::cotask<void> Session::updateUnlock(Unlock::Verification const& method)
{
  auto const msg =
      Unlock::Message(trustchainId(),
                      deviceId(),
                      method,
                      userSecret(),
                      _deviceKeyStore->signatureKeyPair().privateKey);
  try
  {
    TC_AWAIT(_client->updateVerificationKey(msg));
    updateLocalUnlockMethods(method);
  }
  catch (Error::ServerError const& e)
  {
    if (e.httpStatusCode() == 400)
      throw Error::InvalidVerificationKey{e.what()};
    throw;
  }
}

tc::cotask<void> Session::setVerificationMethod(
    Unlock::Verification const& method)
{
  if (!this->_unlockMethods)
    throw Error::OperationCanceled(
        "Cannot call setVerificationMethod() after a verification key has been "
        "used");
  else if (mpark::holds_alternative<VerificationKey>(method))
    throw Error::InvalidArgument(
        "Cannot call setVerificationMethod with a verification key");
  else
  {
    TC_AWAIT(updateUnlock(method));
  }
}

tc::cotask<void> Session::claimProvisionalIdentity(
    SSecretProvisionalIdentity const& sidentity,
    VerificationCode const& verificationCode)
{
  auto const identity = Identity::extract<Identity::SecretProvisionalIdentity>(
      sidentity.string());
  if (identity.target != Identity::TargetType::Email)
    throw Error::formatEx("unsupported provisional identity target {}",
                          identity.target);

  try
  {
    auto tankerKeys = TC_AWAIT(this->_client->getProvisionalIdentityKeys(
        Email{identity.value}, verificationCode));
    if (!tankerKeys)
    {
      throw Error::formatEx<Error::NothingToClaim>(TFMT("nothing to claim {}"),
                                                   identity.value);
    }
    auto block = _blockGenerator.provisionalIdentityClaim(
        _userId,
        SecretProvisionalUser{identity.target,
                              identity.value,
                              identity.appEncryptionKeyPair,
                              tankerKeys->encryptionKeyPair,
                              identity.appSignatureKeyPair,
                              tankerKeys->signatureKeyPair},
        TC_AWAIT(this->_userKeyStore.getLastKeyPair()));
    TC_AWAIT(_client->pushBlock(block));
  }
  catch (Error::ServerError const& e)
  {
    if (e.serverCode() == "invalid_verification_code" ||
        e.serverCode() == "authentication_failed")
    {
      throw Error::InvalidVerificationCode{e.what()};
    }
    else
    {
      throw e;
    }
  }
}

tc::cotask<VerificationKey> Session::generateAndRegisterVerificationKey()
{
  auto const reg = TC_AWAIT(generateVerificationKey());
  TC_AWAIT(registerVerificationKey(*reg));
  TC_RETURN(reg->verificationKey);
}

tc::cotask<bool> Session::isUnlockAlreadySetUp() const
{
  auto const devices = TC_AWAIT(_contactStore.findUserDevices(_userId));
  TC_RETURN(std::any_of(devices.begin(), devices.end(), [](auto const& device) {
    return device.isGhostDevice;
  }));
}

Unlock::Methods Session::registeredUnlockMethods() const
{
  return _unlockMethods;
}

bool Session::hasRegisteredUnlockMethods() const
{
  return !!_unlockMethods;
}

bool Session::hasRegisteredUnlockMethod(Unlock::Method method) const
{
  return !!(_unlockMethods & method);
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
          Error::OperationCanceled("this device was revoked")));
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

tc::cotask<void> Session::onKeyPublishReceived(Entry const& entry)
{
  TC_AWAIT(_keyPublishStore.put(entry.action.get<KeyPublish>()));
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
}
