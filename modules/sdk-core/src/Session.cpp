#include <Tanker/Session.hpp>

#include <Tanker/Actions/KeyPublishToUserGroup.hpp>
#include <Tanker/Actions/UserKeyPair.hpp>
#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DeviceKeyStore.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Groups/GroupUpdater.hpp>
#include <Tanker/Groups/Manager.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/Preregistration.hpp>
#include <Tanker/ReceiveKey.hpp>
#include <Tanker/RecipientNotFound.hpp>
#include <Tanker/ResourceKeyNotFound.hpp>
#include <Tanker/ResourceKeyStore.hpp>
#include <Tanker/Revocation.hpp>
#include <Tanker/Share.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/TrustchainPuller.hpp>
#include <Tanker/TrustchainStore.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/ResourceId.hpp>
#include <Tanker/Types/UnlockKey.hpp>
#include <Tanker/Unlock/Create.hpp>
#include <Tanker/Unlock/Messages.hpp>
#include <Tanker/Unlock/Registration.hpp>
#include <Tanker/UnverifiedEntry.hpp>
#include <Tanker/UserKeyStore.hpp>
#include <Tanker/UserNotFound.hpp>

#include <Tanker/Tracer/ScopeTimer.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <fmt/format.h>
#include <mpark/variant.hpp>
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

using Tanker::Trustchain::UserId;

TLOG_CATEGORY(Session);

namespace Tanker
{
namespace
{

template <typename T, typename F>
auto convertList(std::vector<T> const& source, F&& f)
{
  std::vector<std::result_of_t<F(T)>> ret;
  ret.reserve(source.size());

  std::transform(begin(source), end(source), std::back_inserter(ret), f);
  return ret;
}

// this function can exist because for the moment, a public identity can only
// contain a user id
std::vector<UserId> publicIdentitiesToUserIds(
    std::vector<SPublicIdentity> const& spublicIdentities)
{
  return convertList(spublicIdentities, [](auto&& spublicIdentity) {
    return mpark::get<Identity::PublicPermanentIdentity>(
               Identity::extract<Identity::PublicIdentity>(
                   spublicIdentity.string()))
        .userId;
  });
}

std::vector<GroupId> convertToGroupIds(std::vector<SGroupId> const& sgroupIds)
{
  return convertList(sgroupIds, [](auto&& sgroupId) {
    return cppcodec::base64_rfc4648::decode<GroupId>(sgroupId.string());
  });
}

template <typename S, typename T>
auto toClearId(std::vector<T> const& errorIds,
               std::vector<S> const& sIds,
               std::vector<T> const& Ids)
{
  std::vector<S> clearIds;
  clearIds.reserve(Ids.size());

  for (auto const& wrongId : errorIds)
  {
    auto const badIt = std::find(Ids.begin(), Ids.end(), wrongId);

    assert(badIt != Ids.end() && "Wrong id not found");

    clearIds.push_back(sIds[std::distance(Ids.begin(), badIt)]);
  }
  return clearIds;
}
template <typename T>
std::vector<T> removeDuplicates(std::vector<T> stuff)
{
  std::sort(begin(stuff), end(stuff));
  stuff.erase(std::unique(begin(stuff), end(stuff)), end(stuff));
  return stuff;
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
    _userAccessor(_userId, &_trustchainPuller, &_contactStore),
    _groupAcessor(&_trustchainPuller, &_groupStore),
    _blockGenerator(_trustchainId,
                    _deviceKeyStore->signatureKeyPair().privateKey,
                    _deviceKeyStore->deviceId())
{
  _client->setConnectionHandler(
      [this]() -> tc::cotask<void> { TC_AWAIT(connectionHandler()); });

  _client->blockAvailable.connect(
      [this] { _trustchainPuller.scheduleCatchUp(); });

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
  if (!deviceId.is_null())
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
  auto userIds = publicIdentitiesToUserIds(spublicIdentities);
  auto groupIds = convertToGroupIds(sgroupIds);
  userIds.insert(userIds.begin(), this->_userId);

  TC_AWAIT(_resourceKeyStore.putKey(metadata.resourceId, metadata.key));
  TC_AWAIT(Share::share(_deviceKeyStore->encryptionKeyPair().privateKey,
                        _userAccessor,
                        _groupAcessor,
                        _blockGenerator,
                        *_client,
                        {{metadata.key, metadata.resourceId}},
                        userIds,
                        groupIds));
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
    auto keyPublish = TC_AWAIT(_trustchain.findKeyPublish(resourceId));
    if (!keyPublish)
    {
      TC_AWAIT(_trustchainPuller.scheduleCatchUp());
      keyPublish = TC_AWAIT(_trustchain.findKeyPublish(resourceId));
    }
    if (keyPublish) // do not use else!
    {
      TC_AWAIT(ReceiveKey::decryptAndStoreKey(
          _resourceKeyStore, _userKeyStore, _groupStore, *keyPublish));
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

tc::cotask<void> Session::share(std::vector<ResourceId> const& resourceIds,
                                std::vector<UserId> const& userIds,
                                std::vector<GroupId> const& groupIds)
{
  TC_AWAIT(Share::share(_deviceKeyStore->encryptionKeyPair().privateKey,
                        _resourceKeyStore,
                        _userAccessor,
                        _groupAcessor,
                        _blockGenerator,
                        *_client,
                        resourceIds,
                        userIds,
                        groupIds));
}

tc::cotask<void> Session::share(
    std::vector<SResourceId> const& sresourceIds,
    std::vector<SPublicIdentity> const& spublicIdentities,
    std::vector<SGroupId> const& sgroupIds)
{
  auto userIds = publicIdentitiesToUserIds(spublicIdentities);
  auto groupIds = convertToGroupIds(sgroupIds);
  auto resourceIds = convertList(sresourceIds, [](auto&& resourceId) {
    return cppcodec::base64_rfc4648::decode<ResourceId>(resourceId);
  });

  // we remove ourselves from the recipients
  userIds.erase(
      std::remove_if(begin(userIds),
                     end(userIds),
                     [this](auto&& rec) { return rec == this->_userId; }),
      end(userIds));

  userIds = removeDuplicates(std::move(userIds));
  groupIds = removeDuplicates(std::move(groupIds));
  if (!userIds.empty() || !groupIds.empty())
  {
    try
    {
      TC_AWAIT(share(resourceIds, userIds, groupIds));
    }
    catch (Error::RecipientNotFoundInternal const& e)
    {
      auto const clearPublicIdentities =
          toClearId(e.userIds(), spublicIdentities, userIds);
      auto const clearGids = toClearId(e.groupIds(), sgroupIds, groupIds);
      throw Error::RecipientNotFound(
          fmt::format(
              fmt("unknown public identities: [{:s}], unknown groups: [{:s}]"),
              fmt::join(clearPublicIdentities.begin(),
                        clearPublicIdentities.end(),
                        ", "),
              fmt::join(clearGids.begin(), clearGids.end(), ", ")),
          clearPublicIdentities,
          e.groupIds());
    }
  }
}

tc::cotask<SGroupId> Session::createGroup(
    std::vector<SPublicIdentity> spublicIdentities)
{
  spublicIdentities = removeDuplicates(std::move(spublicIdentities));
  auto userIds = publicIdentitiesToUserIds(spublicIdentities);

  try
  {
    auto const groupId = TC_AWAIT(Groups::Manager::create(
        _userAccessor, _blockGenerator, *_client, userIds));
    // Make sure group's lastBlockHash updates before the next group operation
    TC_AWAIT(syncTrustchain());
    TC_RETURN(groupId);
  }
  catch (Error::UserNotFoundInternal const& e)
  {
    auto const notFoundIdentities =
        toClearId(e.userIds(), spublicIdentities, userIds);
    throw Error::UserNotFound(fmt::format(fmt("Unknown users: {:s}"),
                                          fmt::join(notFoundIdentities.begin(),
                                                    notFoundIdentities.end(),
                                                    ", ")),
                              notFoundIdentities);
  }
  throw std::runtime_error("unreachable code");
}

tc::cotask<void> Session::updateGroupMembers(
    SGroupId const& groupIdString,
    std::vector<SPublicIdentity> spublicIdentitiesToAdd)
{
  auto const groupId = cppcodec::base64_rfc4648::decode<GroupId>(groupIdString);
  spublicIdentitiesToAdd = removeDuplicates(std::move(spublicIdentitiesToAdd));
  auto const usersToAdd = publicIdentitiesToUserIds(spublicIdentitiesToAdd);

  try
  {
    TC_AWAIT(Groups::Manager::updateMembers(_userAccessor,
                                            _blockGenerator,
                                            *_client,
                                            _groupStore,
                                            groupId,
                                            usersToAdd));
  }
  catch (Error::UserNotFoundInternal const& e)
  {
    auto const notFoundIdentities =
        toClearId(e.userIds(), spublicIdentitiesToAdd, usersToAdd);
    throw Error::UserNotFound(fmt::format(fmt("Unknown users: {:s}"),
                                          fmt::join(notFoundIdentities.begin(),
                                                    notFoundIdentities.end(),
                                                    ", ")),
                              notFoundIdentities);
  }

  // Make sure group's lastBlockHash updates before the next group operation
  TC_AWAIT(syncTrustchain());
}

tc::cotask<std::unique_ptr<Unlock::Registration>> Session::generateUnlockKey()
{
  TC_RETURN(Unlock::generate(
      _userId, TC_AWAIT(_userKeyStore.getLastKeyPair()), _blockGenerator));
}

tc::cotask<void> Session::registerUnlockKey(
    Unlock::Registration const& registration)
{
  TC_AWAIT(_client->pushBlock(registration.block));
}

tc::cotask<void> Session::createUnlockKey(
    Unlock::CreationOptions const& options)
{
  auto const reg = TC_AWAIT(generateUnlockKey());
  auto const msg = Unlock::Message(
      trustchainId(),
      deviceId(),
      Unlock::UpdateOptions(
          options.get<Email>(), options.get<Password>(), reg->unlockKey),
      userSecret(),
      _deviceKeyStore->signatureKeyPair().privateKey);
  try
  {
    TC_AWAIT(_client->pushBlock(reg->block));
    TC_AWAIT(_client->createUnlockKey(msg));
    updateLocalUnlockMethods(options);
  }
  catch (Error::ServerError const& e)
  {
    if (e.httpStatusCode() == 500)
      throw Error::InternalError(e.what());
    else if (e.httpStatusCode() == 409)
      throw Error::UnlockKeyAlreadyExists(
          "An unlock key has already been registered");
    else
      throw;
  }
}

void Session::updateLocalUnlockMethods(
    Unlock::RegistrationOptions const& options)
{
  if (options.get<Email>().has_value())
    _unlockMethods |= Unlock::Method::Email;
  if (options.get<Password>().has_value())
    _unlockMethods |= Unlock::Method::Password;
}

tc::cotask<void> Session::updateUnlock(Unlock::UpdateOptions const& options)
{
  auto const msg =
      Unlock::Message(trustchainId(),
                      deviceId(),
                      options,
                      userSecret(),
                      _deviceKeyStore->signatureKeyPair().privateKey);
  try
  {
    TC_AWAIT(_client->updateUnlockKey(msg));
    updateLocalUnlockMethods(
        std::forward_as_tuple(options.get<Email>(), options.get<Password>()));
  }
  catch (Error::ServerError const& e)
  {
    if (e.httpStatusCode() == 400)
      throw Error::InvalidUnlockKey{e.what()};
    throw;
  }
}

tc::cotask<void> Session::registerUnlock(
    Unlock::RegistrationOptions const& options)
{
  if (!this->_unlockMethods)
    TC_AWAIT(createUnlockKey(options));
  else
    TC_AWAIT(updateUnlock(Unlock::UpdateOptions{
        options.get<Email>(), options.get<Password>(), nonstd::nullopt}));
}

tc::cotask<UnlockKey> Session::generateAndRegisterUnlockKey()
{
  auto const reg = TC_AWAIT(generateUnlockKey());
  TC_AWAIT(registerUnlockKey(*reg));
  TC_RETURN(reg->unlockKey);
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
  auto const& deviceCreation =
      mpark::get<Trustchain::Actions::DeviceCreation>(entry.action.variant());
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
  auto const& deviceRevocation =
      mpark::get<Trustchain::Actions::DeviceRevocation>(entry.action.variant());

  if (deviceRevocation.deviceId() == this->deviceId())
  {
    TINFO("This device has been revoked");
    if (!_ready.get_future().is_ready())
    {
      _ready.set_exception(std::make_exception_ptr(
          Error::OperationCanceled("this device was revoked")));
    }
    TC_AWAIT(nukeDatabase());
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
  TC_AWAIT(GroupUpdater::applyEntry(_groupStore, _userKeyStore, entry));
}

tc::cotask<void> Session::onProvisionalIdentityClaimEntry(Entry const& entry)
{
  TC_AWAIT(Preregistration::applyEntry(
      _userKeyStore, _provisionalUserKeysStore, entry));
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
