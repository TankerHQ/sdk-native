#include "TrustchainBuilder.hpp"

#include <Tanker/Entry.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Groups/EntryGenerator.hpp>
#include <Tanker/Groups/GroupEncryptedKey.hpp>
#include <Tanker/Groups/Manager.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Revocation.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Share.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>
#include <Tanker/Trustchain/ComputeHash.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Types/SUserId.hpp>
#include <Tanker/Users/EntryGenerator.hpp>
#include <Tanker/Users/LocalUser.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Entries.hpp>

#include <algorithm>
#include <cstring>

using namespace Tanker::Trustchain::Actions;
using namespace Tanker::Trustchain;
using namespace Tanker;

TrustchainBuilder::TrustchainBuilder()
{
  auto const keyPair = Tanker::Crypto::makeSignatureKeyPair();
  auto const nature = Nature::TrustchainCreation;
  Crypto::Hash const author{};
  TrustchainCreation const action{keyPair.publicKey};
  auto const hash =
      computeHash(nature, author, Serialization::serialize(action));
  _context =
      Trustchain::Context{static_cast<TrustchainId>(hash), keyPair.publicKey};
  _trustchainPrivateSignatureKey = keyPair.privateKey;

  // root block is not signed
  _entries.emplace_back(
      _context.id(), 1, author, action, hash, Crypto::Signature{});
}

namespace
{
TrustchainBuilder::Device createDevice()
{
  return TrustchainBuilder::Device{
      Tanker::DeviceKeys::create(),
      {}, // deviceId will be filled in later
      {}, // userId will be filled in later
      {}, // delegation will be filled in later
  };
}
}

Tanker::Users::Device TrustchainBuilder::Device::asTankerDevice() const
{
  return Tanker::Users::Device(id,
                               userId,
                               keys.signatureKeyPair.publicKey,
                               keys.encryptionKeyPair.publicKey,
                               // This completely arbitrary...
                               true,
                               isRevoked);
}

Tanker::Users::User TrustchainBuilder::User::asTankerUser() const
{
  Tanker::Users::User tankerUser{
      userId,
      userKeys.empty() ? std::optional<Tanker::Crypto::PublicEncryptionKey>() :
                         userKeys.back().keyPair.publicKey,
      {}};

  for (auto const& device : devices)
    tankerUser.addDevice(device.asTankerDevice());
  return tankerUser;
}

std::optional<TrustchainBuilder::Device> TrustchainBuilder::User::findDevice(
    Tanker::Trustchain::DeviceId const& id) const
{
  for (auto const& device : devices)
    if (device.id == id)
      return device;
  return std::nullopt;
}

Tanker::ExternalGroup TrustchainBuilder::InternalGroup::asExternalGroup() const
{
  Tanker::ExternalGroup extGroup{
      tankerGroup.id,
      tankerGroup.signatureKeyPair.publicKey,
      encryptedPrivateSignatureKey,
      tankerGroup.encryptionKeyPair.publicKey,
      tankerGroup.lastBlockHash,
  };
  return extGroup;
}

Tanker::Trustchain::Context const& TrustchainBuilder::trustchainContext() const
{
  return _context;
}

TrustchainId const& TrustchainBuilder::trustchainId() const
{
  return trustchainContext().id();
}

Crypto::PrivateSignatureKey const& TrustchainBuilder::trustchainPrivateKey()
    const
{
  return _trustchainPrivateSignatureKey;
}

Crypto::PublicSignatureKey const& TrustchainBuilder::trustchainPublicKey() const
{
  return trustchainContext().publicSignatureKey();
}

auto TrustchainBuilder::makeUser(std::string const& suserId) -> ResultUser
{
  return makeUser3(suserId);
}

auto TrustchainBuilder::makeUser1(std::string const& suserId) -> ResultUser
{
  if (findUser(suserId))
    throw Errors::AssertionError(fmt::format("{} already exists", suserId));

  auto device = createDevice();
  auto const daUserId = SUserId{suserId};
  User user{daUserId,
            obfuscateUserId(daUserId, trustchainId()),
            {device},
            {},
            _entries.size() + 1,
            {_entries.front()}};
  auto const delegation =
      Identity::makeDelegation(user.userId, trustchainPrivateKey());

  auto const clientEntry =
      Users::createDeviceV1Entry(trustchainId(),
                                 Crypto::Hash{trustchainId()},
                                 delegation,
                                 device.keys.signatureKeyPair.publicKey,
                                 device.keys.encryptionKeyPair.publicKey);
  auto const serverEntry =
      clientToServerEntry(clientEntry, _entries.size() + 1);

  user.devices[0].delegation = delegation;
  user.devices[0].id = static_cast<DeviceId>(serverEntry.hash());
  user.devices[0].userId = user.userId;
  _users.push_back(user);
  _entries.push_back(serverEntry);

  return {user, serverEntry};
}

auto TrustchainBuilder::makeUser3(std::string const& suserId) -> ResultUser
{
  if (findUser(suserId))
    throw Errors::AssertionError(fmt::format("{} already exists", suserId));

  auto device = createDevice();
  auto const daUserId = SUserId{suserId};
  User user{daUserId,
            Tanker::obfuscateUserId(daUserId, trustchainId()),
            {device},
            {{Tanker::Crypto::makeEncryptionKeyPair(), _entries.size() + 1}},
            _entries.size() + 1,
            {_entries.front()}};

  auto const delegation =
      Identity::makeDelegation(user.userId, trustchainPrivateKey());

  auto const clientEntry =
      Users::createNewUserEntry(trustchainId(),
                                delegation,
                                device.keys.signatureKeyPair.publicKey,
                                device.keys.encryptionKeyPair.publicKey,
                                user.userKeys.back().keyPair);
  auto const serverEntry =
      clientToServerEntry(clientEntry, _entries.size() + 1);

  user.devices[0].id = static_cast<DeviceId>(serverEntry.hash());
  user.devices[0].userId = user.userId;
  user.devices[0].delegation = delegation;
  _users.push_back(user);

  _entries.push_back(serverEntry);

  return {user, serverEntry};
}

auto TrustchainBuilder::makeDevice(std::string const& suserId,
                                   int validatorDeviceIndex) -> ResultDevice
{
  return makeDevice3(suserId, validatorDeviceIndex);
}

auto TrustchainBuilder::makeDevice1(std::string const& p,
                                    int validatorDeviceIndex) -> ResultDevice
{
  auto const suserId = SUserId{p};
  auto user = findMutableUser(suserId);

  auto device = createDevice();

  // the device that will validate this device
  auto const& validatorDevice = user->devices.at(validatorDeviceIndex);

  auto const delegation = Identity::makeDelegation(
      user->userId, validatorDevice.keys.signatureKeyPair.privateKey);

  auto const clientEntry =
      Users::createDeviceV1Entry(trustchainId(),
                                 static_cast<Crypto::Hash>(validatorDevice.id),
                                 delegation,
                                 device.keys.signatureKeyPair.publicKey,
                                 device.keys.encryptionKeyPair.publicKey);
  auto const serverEntry =
      clientToServerEntry(clientEntry, _entries.size() + 1);

  device.id = static_cast<DeviceId>(serverEntry.hash());
  device.userId = user->userId;
  device.delegation = delegation;
  user->devices.push_back(device);

  user->entries.push_back(serverEntry);
  _entries.push_back(serverEntry);

  return {device, user->asTankerUser(), serverEntry};
}

auto TrustchainBuilder::makeDevice3(std::string const& p,
                                    int validatorDeviceIndex) -> ResultDevice
{
  auto const suserId = SUserId{p};
  auto user = findMutableUser(suserId);

  if (user->userKeys.empty()) // upgrading the user
  {
    user->userKeys.push_back(
        {Tanker::Crypto::makeEncryptionKeyPair(), _entries.size() + 1});
  }

  auto device = createDevice();

  // the device that will validate this device
  auto const& validatorDevice = user->devices.at(validatorDeviceIndex);

  auto const delegation = Identity::makeDelegation(
      user->userId, validatorDevice.keys.signatureKeyPair.privateKey);
  auto const clientEntry =
      Users::createNewDeviceEntry(trustchainId(),
                                  validatorDevice.id,
                                  delegation,
                                  device.keys.signatureKeyPair.publicKey,
                                  device.keys.encryptionKeyPair.publicKey,
                                  user->userKeys.back().keyPair);
  auto const serverEntry =
      clientToServerEntry(clientEntry, _entries.size() + 1);

  device.id = static_cast<DeviceId>(serverEntry.hash());
  device.userId = user->userId;
  device.delegation = delegation;
  user->devices.push_back(device);
  user->entries.push_back(serverEntry);

  _entries.push_back(serverEntry);

  return {device, user->asTankerUser(), serverEntry};
}

TrustchainBuilder::ProvisionalUser TrustchainBuilder::makeProvisionalUser(
    std::string const& email)
{
  auto const secretProvisionalUser = ProvisionalUsers::SecretUser{
      Tanker::Identity::TargetType::Email,
      email,
      Crypto::makeEncryptionKeyPair(),
      Crypto::makeEncryptionKeyPair(),
      Crypto::makeSignatureKeyPair(),
      Crypto::makeSignatureKeyPair(),
  };
  auto const publicProvisionalUser = ProvisionalUsers::PublicUser{
      secretProvisionalUser.appSignatureKeyPair.publicKey,
      secretProvisionalUser.appEncryptionKeyPair.publicKey,
      secretProvisionalUser.tankerSignatureKeyPair.publicKey,
      secretProvisionalUser.tankerEncryptionKeyPair.publicKey,
  };
  auto const publicProvisionalIdentity = Identity::PublicProvisionalIdentity{
      trustchainId(),
      secretProvisionalUser.target,
      secretProvisionalUser.value,
      secretProvisionalUser.appSignatureKeyPair.publicKey,
      secretProvisionalUser.appEncryptionKeyPair.publicKey,
  };
  return ProvisionalUser{
      secretProvisionalUser,
      publicProvisionalUser,
      SPublicIdentity(to_string(publicProvisionalIdentity)),
  };
}

ServerEntry TrustchainBuilder::claimProvisionalIdentity(
    std::string const& suserId,
    Tanker::ProvisionalUsers::SecretUser const& provisionalUser,
    int authorDeviceIndex)
{

  auto user = findMutableUser(SUserId{suserId});
  auto const& authorDevice = user->devices.at(authorDeviceIndex);

  auto const clientEntry = Users::createProvisionalIdentityClaimEntry(
      trustchainId(),
      authorDevice.id,
      authorDevice.keys.signatureKeyPair.privateKey,
      user->userId,
      provisionalUser,
      user->userKeys.back().keyPair);
  auto const serverEntry =
      clientToServerEntry(clientEntry, _entries.size() + 1);

  user->entries.push_back(serverEntry);
  _entries.push_back(serverEntry);
  return serverEntry;
}

TrustchainBuilder::ResultGroup TrustchainBuilder::makeGroup(
    Device const& author,
    std::vector<User> const& users,
    std::vector<Tanker::ProvisionalUsers::PublicUser> const& provisionalUsers)
{
  return makeGroup2(author, users, provisionalUsers);
}

namespace
{
UserGroupCreation::v1::SealedPrivateEncryptionKeysForUsers
generateGroupKeysForUsers(
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
    std::vector<TrustchainBuilder::User> const& users)
{
  UserGroupCreation::v1::SealedPrivateEncryptionKeysForUsers keysForUsers;
  for (auto const& user : users)
  {
    if (user.userKeys.empty())
      throw std::runtime_error(
          "TrustchainBuilder: can't add a user without user key to a group");
    keysForUsers.emplace_back(
        user.userKeys.back().keyPair.publicKey,
        Crypto::sealEncrypt(groupPrivateEncryptionKey,
                            user.userKeys.back().keyPair.publicKey));
  }
  return keysForUsers;
}

std::vector<TrustchainBuilder::User> getOnlyNewMembers(
    std::vector<SUserId> oldMembers, std::vector<TrustchainBuilder::User> toAdd)
{
  std::vector<TrustchainBuilder::User> newUsers;
  newUsers.reserve(toAdd.size());
  std::remove_copy_if(toAdd.begin(),
                      toAdd.end(),
                      std::back_inserter(newUsers),
                      [&](auto const& user) {
                        return std::find(oldMembers.begin(),
                                         oldMembers.end(),
                                         user.suserId) != oldMembers.end();
                      });
  auto const comparator = [](auto const& a, auto const& b) {
    return a.suserId < b.suserId;
  };
  std::sort(newUsers.begin(), newUsers.end(), comparator);
  newUsers.erase(std::unique(newUsers.begin(), newUsers.end(), comparator),
                 newUsers.end());
  return newUsers;
}
}

TrustchainBuilder::ResultGroup TrustchainBuilder::makeGroup1(
    Device const& author, std::vector<User> const& users)
{
  auto const signatureKeyPair = Crypto::makeSignatureKeyPair();
  auto const encryptionKeyPair = Crypto::makeEncryptionKeyPair();
  auto const keysForUsers =
      generateGroupKeysForUsers(encryptionKeyPair.privateKey, users);

  auto const clientEntry = Groups::createUserGroupCreationV1Entry(
      signatureKeyPair,
      encryptionKeyPair.publicKey,
      keysForUsers,
      trustchainId(),
      author.id,
      author.keys.signatureKeyPair.privateKey);

  auto const serverEntry =
      clientToServerEntry(clientEntry, _entries.size() + 1);
  _entries.push_back(serverEntry);

  Tanker::InternalGroup tgroup{
      GroupId{signatureKeyPair.publicKey},
      signatureKeyPair,
      encryptionKeyPair,
      serverEntry.hash(),
  };

  std::vector<SUserId> members;
  for (auto const& user : users)
    members.push_back(user.suserId);

  auto const encryptedPrivateSignatureKey = serverEntry.action()
                                                .get<UserGroupCreation>()
                                                .get<UserGroupCreation::v1>()
                                                .sealedPrivateSignatureKey();
  InternalGroup group{tgroup, encryptedPrivateSignatureKey, members, {}};

  _groups.insert(group);

  return {group, serverEntry};
}

TrustchainBuilder::ResultGroup TrustchainBuilder::makeGroup2(
    Device const& author,
    std::vector<User> const& users,
    std::vector<Tanker::ProvisionalUsers::PublicUser> const& provisionalUsers)
{
  auto const signatureKeyPair = Crypto::makeSignatureKeyPair();
  auto const encryptionKeyPair = Crypto::makeEncryptionKeyPair();

  std::vector<Tanker::Users::User> tusers;
  for (auto const& user : users)
    tusers.push_back(user.asTankerUser());

  auto const clientEntry = Groups::Manager::makeUserGroupCreationEntry(
      tusers,
      provisionalUsers,
      signatureKeyPair,
      encryptionKeyPair,
      trustchainId(),
      author.id,
      author.keys.signatureKeyPair.privateKey);

  auto const serverEntry =
      clientToServerEntry(clientEntry, _entries.size() + 1);
  _entries.push_back(serverEntry);

  Tanker::InternalGroup tgroup{
      GroupId{signatureKeyPair.publicKey},
      signatureKeyPair,
      encryptionKeyPair,
      serverEntry.hash(),
  };

  std::vector<SUserId> members;
  for (auto const& user : users)
    members.push_back(user.suserId);

  auto const encryptedPrivateSignatureKey = serverEntry.action()
                                                .get<UserGroupCreation>()
                                                .get<UserGroupCreation::v2>()
                                                .sealedPrivateSignatureKey();
  auto const provisionalMembers = serverEntry.action()
                                      .get<UserGroupCreation>()
                                      .get<UserGroupCreation::v2>()
                                      .provisionalMembers();

  InternalGroup group{
      tgroup, encryptedPrivateSignatureKey, members, provisionalMembers};

  _groups.insert(group);

  return {group, serverEntry};
}

TrustchainBuilder::ResultGroup TrustchainBuilder::addUserToGroup(
    Device const& author, InternalGroup group, std::vector<User> const& users)
{
  auto const newUsers = getOnlyNewMembers(group.members, users);

  auto const keysForUsers = generateGroupKeysForUsers(
      group.tankerGroup.encryptionKeyPair.privateKey, newUsers);

  auto const clientEntry = Groups::createUserGroupAdditionV1Entry(
      group.tankerGroup.signatureKeyPair,
      group.tankerGroup.lastBlockHash,
      keysForUsers,
      trustchainId(),
      author.id,
      author.keys.signatureKeyPair.privateKey);

  auto const serverEntry =
      clientToServerEntry(clientEntry, _entries.size() + 1);
  _entries.push_back(serverEntry);

  group.tankerGroup.lastBlockHash = serverEntry.hash();

  std::transform(newUsers.begin(),
                 newUsers.end(),
                 std::back_inserter(group.members),
                 [](auto const& user) { return user.suserId; });

  // replace group in _groups
  _groups.erase(group);
  _groups.insert(group);

  return {group, serverEntry};
}

TrustchainBuilder::ResultGroup TrustchainBuilder::addUserToGroup2(
    Device const& author,
    InternalGroup group,
    std::vector<User> const& users,
    std::vector<Tanker::ProvisionalUsers::PublicUser> const& provisionalUsers)
{
  auto const newUsers = getOnlyNewMembers(group.members, users);

  std::vector<Tanker::Users::User> tusers;
  for (auto const& user : newUsers)
    tusers.push_back(user.asTankerUser());

  auto const clientEntry = Groups::Manager::makeUserGroupAdditionEntry(
      tusers,
      provisionalUsers,
      group.tankerGroup,
      trustchainId(),
      author.id,
      author.keys.signatureKeyPair.privateKey);

  auto const serverEntry =
      clientToServerEntry(clientEntry, _entries.size() + 1);
  _entries.push_back(serverEntry);

  auto const newProvisionalMembers = serverEntry.action()
                                         .get<UserGroupAddition>()
                                         .get<UserGroupAddition::v2>()
                                         .provisionalMembers();

  group.provisionalMembers.insert(group.provisionalMembers.end(),
                                  newProvisionalMembers.begin(),
                                  newProvisionalMembers.end());
  group.tankerGroup.lastBlockHash = serverEntry.hash();

  std::transform(newUsers.begin(),
                 newUsers.end(),
                 std::back_inserter(group.members),
                 [](auto const& user) { return user.suserId; });

  // replace group in _groups
  _groups.erase(group);
  _groups.insert(group);

  return {group, serverEntry};
}

ServerEntry TrustchainBuilder::shareToUser(Device const& sender,
                                           User const& receiver,
                                           ResourceId const& resourceId,
                                           Crypto::SymmetricKey const& key)
{
  if (receiver.userKeys.empty())
    throw std::runtime_error("can't shareToUser if the user has no user key");

  auto const receiverPublicKey = receiver.userKeys.back().keyPair.publicKey;

  auto const serverEntry = clientToServerEntry(
      Share::makeKeyPublishToUser(trustchainId(),
                                  sender.id,
                                  sender.keys.signatureKeyPair.privateKey,
                                  receiverPublicKey,
                                  resourceId,
                                  key),
      _entries.size() + 1);

  _entries.push_back(serverEntry);

  return serverEntry;
}

ServerEntry TrustchainBuilder::shareToUserGroup(Device const& sender,
                                                InternalGroup const& receiver,
                                                ResourceId const& resourceId,
                                                Crypto::SymmetricKey const& key)
{
  auto const receiverPublicKey =
      receiver.tankerGroup.encryptionKeyPair.publicKey;

  auto const encryptedKey = Crypto::sealEncrypt(key, receiverPublicKey);

  KeyPublishToUserGroup keyPublish{receiverPublicKey, resourceId, encryptedKey};

  auto const nature = Nature::KeyPublishToUserGroup;
  auto const author = static_cast<Crypto::Hash>(sender.id);
  auto const hash =
      computeHash(nature, author, Serialization::serialize(keyPublish));
  auto const signature =
      Crypto::sign(hash, sender.keys.signatureKeyPair.privateKey);
  _entries.emplace_back(
      trustchainId(), _entries.size() + 1, author, keyPublish, hash, signature);

  return _entries.back();
}

ServerEntry TrustchainBuilder::shareToProvisionalUser(
    Device const& sender,
    ProvisionalUsers::PublicUser const& receiver,
    ResourceId const& resourceId,
    Crypto::SymmetricKey const& key)
{
  auto const encryptedKeyOnce =
      Crypto::sealEncrypt(key, receiver.appEncryptionPublicKey);
  auto const encryptedKeyTwice =
      Crypto::sealEncrypt(encryptedKeyOnce, receiver.tankerEncryptionPublicKey);

  KeyPublishToProvisionalUser keyPublish{receiver.appSignaturePublicKey,
                                         resourceId,
                                         receiver.tankerSignaturePublicKey,
                                         encryptedKeyTwice};

  auto const nature = Nature::KeyPublishToProvisionalUser;
  auto const author = static_cast<Crypto::Hash>(sender.id);
  auto const hash =
      computeHash(nature, author, Serialization::serialize(keyPublish));
  auto const signature =
      Crypto::sign(hash, sender.keys.signatureKeyPair.privateKey);
  _entries.emplace_back(
      trustchainId(), _entries.size() + 1, author, keyPublish, hash, signature);

  return _entries.back();
}

TrustchainBuilder::User* TrustchainBuilder::findMutableUserByDeviceId(
    Trustchain::DeviceId const& deviceId)
{
  auto const user =
      std::find_if(_users.begin(), _users.end(), [&](auto const user) {
        return std::find_if(user.devices.begin(),
                            user.devices.end(),
                            [&](Device const& device) {
                              return device.id == deviceId;
                            }) != user.devices.end();
      });

  if (user == _users.end())
    return nullptr;

  return &*user;
}

ServerEntry TrustchainBuilder::revokeDevice1(Device const& sender,
                                             Device const& target,
                                             bool unsafe)
{
  auto senderUser = findMutableUserByDeviceId(sender.id);
  auto targetUser = findMutableUserByDeviceId(target.id);

  if (!senderUser)
    throw std::runtime_error("TrustchainBuilder: revoke: unknown sender user");
  if (!targetUser)
    throw std::runtime_error("TrustchainBuilder: revoke: unknown target user");

  if (senderUser != targetUser && !unsafe)
  {
    throw std::runtime_error(
        "TrustchainBuilder: cannot revoke a device from another user");
  }

  auto const revocation = DeviceRevocation1{target.id};

  auto const nature = Nature::DeviceRevocation;
  auto const author = static_cast<Crypto::Hash>(sender.id);
  auto const hash =
      computeHash(nature, author, Serialization::serialize(revocation));
  auto const signature =
      Crypto::sign(hash, sender.keys.signatureKeyPair.privateKey);
  _entries.emplace_back(
      trustchainId(), _entries.size() + 1, author, revocation, hash, signature);

  auto const revokedDevice =
      std::find_if(targetUser->devices.begin(),
                   targetUser->devices.end(),
                   [&](auto const dev) { return dev.id == target.id; });
  targetUser->devices.erase(revokedDevice);
  targetUser->entries.push_back(_entries.back());

  return _entries.back();
}

ServerEntry TrustchainBuilder::revokeDevice2(Device const& sender,
                                             Device const& target,
                                             bool unsafe)
{
  auto senderUser = findMutableUserByDeviceId(sender.id);
  auto targetUser = findMutableUserByDeviceId(target.id);

  if (!senderUser)
    throw std::runtime_error("TrustchainBuilder: revoke: unknown sender user");
  if (!targetUser)
    throw std::runtime_error("TrustchainBuilder: revoke: unknown target user");

  if (senderUser != targetUser && !unsafe)
  {
    throw std::runtime_error(
        "TrustchainBuilder: cannot revoke a device from another user");
  }
  auto const newEncryptionKey = Crypto::makeEncryptionKeyPair();
  auto const tankerUser = targetUser->asTankerUser();
  auto oldPublicEncryptionKey = Crypto::PublicEncryptionKey{};
  auto encryptedKeyForPreviousUserKey = Crypto::SealedPrivateEncryptionKey{};
  if (tankerUser.userKey())
  {
    oldPublicEncryptionKey = *tankerUser.userKey();
    encryptedKeyForPreviousUserKey =
        Crypto::sealEncrypt(targetUser->userKeys.back().keyPair.privateKey,
                            newEncryptionKey.publicKey);
  }

  auto const userKeys = Revocation::encryptPrivateKeyForDevices(
      targetUser->asTankerUser(), target.id, newEncryptionKey.privateKey);

  auto const clientEntry =
      Users::revokeDeviceEntry(trustchainId(),
                               sender.id,
                               sender.keys.signatureKeyPair.privateKey,
                               target.id,
                               newEncryptionKey.publicKey,
                               encryptedKeyForPreviousUserKey,
                               oldPublicEncryptionKey,
                               userKeys);

  auto const serverEntry =
      clientToServerEntry(clientEntry, _entries.size() + 1);
  _entries.push_back(serverEntry);

  targetUser->userKeys.push_back(UserKey{newEncryptionKey, _entries.size()});
  targetUser->entries.push_back(serverEntry);
  auto const revokedDevice =
      std::find_if(targetUser->devices.begin(),
                   targetUser->devices.end(),
                   [&](auto const dev) { return dev.id == target.id; });
  revokedDevice->isRevoked = true;

  return _entries.back();
}

std::optional<TrustchainBuilder::User> TrustchainBuilder::findUser(
    std::string const& suserId) const
{
  auto user =
      const_cast<TrustchainBuilder*>(this)->findMutableUser(SUserId{suserId});
  if (user)
    return *user;
  return std::nullopt;
}

TrustchainBuilder::User* TrustchainBuilder::findMutableUser(
    SUserId const& suserId)
{
  auto const it =
      std::find_if(_users.begin(), _users.end(), [&](auto const& user) {
        return user.suserId == suserId;
      });
  if (it == _users.end())
    return nullptr;
  return std::addressof(*it);
}

std::unique_ptr<Tanker::Users::LocalUserStore>
TrustchainBuilder::makeLocalUserStore(User const& user,
                                      Tanker::DataStore::ADatabase* conn) const
{
  auto store = std::make_unique<Users::LocalUserStore>(conn);
  std::vector<Crypto::EncryptionKeyPair> keys(user.userKeys.begin(),
                                              user.userKeys.end());
  auto const& device = user.devices.front();
  store->putLocalUser(
      Tanker::Users::LocalUser(user.userId, device.id, device.keys, keys));
  return store;
}

std::unique_ptr<Tanker::ProvisionalUserKeysStore>
TrustchainBuilder::makeProvisionalUserKeysStoreWith(
    std::vector<ProvisionalUser> const& provisionalUsers,
    Tanker::DataStore::ADatabase* conn) const
{
  auto provisionalUserKeysStore =
      std::make_unique<Tanker::ProvisionalUserKeysStore>(conn);
  for (auto const& provisionalUser : provisionalUsers)
  {
    AWAIT_VOID(provisionalUserKeysStore->putProvisionalUserKeys(
        provisionalUser.secretProvisionalUser.appSignatureKeyPair.publicKey,
        provisionalUser.secretProvisionalUser.tankerSignatureKeyPair.publicKey,
        {
            provisionalUser.secretProvisionalUser.appEncryptionKeyPair,
            provisionalUser.secretProvisionalUser.tankerEncryptionKeyPair,
        }));
  }
  return provisionalUserKeysStore;
}

std::vector<Group> TrustchainBuilder::getGroupsOfUser(
    TrustchainBuilder::User const& user) const
{
  std::vector<Group> result;
  for (auto const& group : _groups)
  {
    if (std::find(group.members.begin(), group.members.end(), user.suserId) !=
        group.members.end())
      result.push_back(group.tankerGroup);
    else
      result.push_back(group.asExternalGroup());
  }
  return result;
}

std::unique_ptr<Tanker::Groups::Store> TrustchainBuilder::makeGroupStore(
    TrustchainBuilder::User const& user,
    Tanker::DataStore::ADatabase* conn) const
{
  auto result = std::make_unique<Tanker::Groups::Store>(conn);
  for (auto const& group : getGroupsOfUser(user))
    AWAIT_VOID(result->put(group));
  return result;
}

std::unique_ptr<Tanker::Groups::Store> TrustchainBuilder::makeGroupStore(
    std::vector<Trustchain::GroupId> const& groups,
    Tanker::DataStore::ADatabase* conn) const
{
  auto result = std::make_unique<Tanker::Groups::Store>(conn);
  for (auto const& groupId : groups)
  {
    auto const groupIt =
        std::find_if(_groups.begin(), _groups.end(), [&](auto const& g) {
          return g.tankerGroup.id == groupId;
        });

    if (groupIt == _groups.end())
      throw std::runtime_error(
          "TrustchainBuilder: unknown group in makeGroupStore");

    AWAIT_VOID(result->put(groupIt->asExternalGroup()));
  }
  return result;
}

std::vector<ServerEntry> const& TrustchainBuilder::entries() const
{
  return _entries;
}

std::vector<TrustchainBuilder::InternalGroup> TrustchainBuilder::groups() const
{
  return std::vector<InternalGroup>(_groups.begin(), _groups.end());
}

std::vector<TrustchainBuilder::User> const& TrustchainBuilder::users() const
{
  return _users;
}
