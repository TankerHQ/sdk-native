#include "TrustchainBuilder.hpp"

#include <Tanker/Entry.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Groups/EntryGenerator.hpp>
#include <Tanker/Groups/GroupEncryptedKey.hpp>
#include <Tanker/Groups/Manager.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Share.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>
#include <Tanker/Trustchain/ComputeHash.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Types/SUserId.hpp>
#include <Tanker/Users/ContactStore.hpp>
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
  : _trustchainKeyPair(Tanker::Crypto::makeSignatureKeyPair())
{
  auto const nature = Nature::TrustchainCreation;
  Crypto::Hash const author{};
  TrustchainCreation const action{_trustchainKeyPair.publicKey};
  auto const hash =
      computeHash(nature, author, Serialization::serialize(action));
  _trustchainId = static_cast<TrustchainId>(hash);

  // root block is not signed
  _entries.emplace_back(
      _trustchainId, 1, author, action, hash, Crypto::Signature{});
}

namespace
{
TrustchainBuilder::Device createDevice()
{
  return TrustchainBuilder::Device{
      {
          Tanker::Crypto::makeSignatureKeyPair(),
          Tanker::Crypto::makeEncryptionKeyPair(),
      },
      {}, // deviceId will be filled in later
      {}, // userId will be filled in later
      {}, // delegation will be filled in later
      {}  // blockIndex will be filled in later
  };
}
}

Tanker::Users::Device TrustchainBuilder::Device::asTankerDevice() const
{
  return Tanker::Users::Device(id,
                               userId,
                               blockIndex,
                               // This completely arbitrary...
                               true,
                               keys.signatureKeyPair.publicKey,
                               keys.encryptionKeyPair.publicKey);
}

Tanker::Users::User TrustchainBuilder::User::asTankerUser() const
{
  Tanker::Users::User tankerUser{
      userId,
      userKeys.empty() ? std::optional<Tanker::Crypto::PublicEncryptionKey>() :
                         userKeys.back().keyPair.publicKey,
      std::vector<Tanker::Users::Device>()};

  tankerUser.devices.reserve(devices.size());
  std::transform(devices.begin(),
                 devices.end(),
                 std::back_inserter(tankerUser.devices),
                 [](auto const& device) { return device.asTankerDevice(); });

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
      tankerGroup.lastBlockIndex,
  };
  return extGroup;
}

TrustchainId const& TrustchainBuilder::trustchainId() const
{
  return _trustchainId;
}

Crypto::PrivateSignatureKey const& TrustchainBuilder::trustchainPrivateKey()
    const
{
  return _trustchainKeyPair.privateKey;
}

Crypto::PublicSignatureKey const& TrustchainBuilder::trustchainPublicKey() const
{
  return _trustchainKeyPair.publicKey;
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
  User user{
      daUserId,
      obfuscateUserId(daUserId, _trustchainId),
      {device},
      {},
      _entries.size() + 1,
  };
  auto const delegation =
      Identity::makeDelegation(user.userId, _trustchainKeyPair.privateKey);

  auto const clientEntry =
      Users::createDeviceV1Entry(_trustchainId,
                                 Crypto::Hash{_trustchainId},
                                 delegation,
                                 device.keys.signatureKeyPair.publicKey,
                                 device.keys.encryptionKeyPair.publicKey);
  auto const serverEntry =
      clientToServerEntry(clientEntry, _entries.size() + 1);

  user.devices[0].delegation = delegation;
  user.devices[0].id = static_cast<DeviceId>(serverEntry.hash());
  user.devices[0].userId = user.userId;
  user.devices[0].blockIndex = serverEntry.index();
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
  User user{
      daUserId,
      Tanker::obfuscateUserId(daUserId, _trustchainId),
      {device},
      {{Tanker::Crypto::makeEncryptionKeyPair(), _entries.size() + 1}},
      _entries.size() + 1,
  };

  auto const delegation =
      Identity::makeDelegation(user.userId, _trustchainKeyPair.privateKey);

  auto const clientEntry =
      Users::createNewUserEntry(_trustchainId,
                                delegation,
                                device.keys.signatureKeyPair.publicKey,
                                device.keys.encryptionKeyPair.publicKey,
                                user.userKeys.back().keyPair);
  auto const serverEntry =
      clientToServerEntry(clientEntry, _entries.size() + 1);

  user.devices[0].id = static_cast<DeviceId>(serverEntry.hash());
  user.devices[0].userId = user.userId;
  user.devices[0].delegation = delegation;
  user.devices[0].blockIndex = serverEntry.index();
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
      Users::createDeviceV1Entry(_trustchainId,
                                 static_cast<Crypto::Hash>(validatorDevice.id),
                                 delegation,
                                 device.keys.signatureKeyPair.publicKey,
                                 device.keys.encryptionKeyPair.publicKey);
  auto const serverEntry =
      clientToServerEntry(clientEntry, _entries.size() + 1);

  device.id = static_cast<DeviceId>(serverEntry.hash());
  device.userId = user->userId;
  device.delegation = delegation;
  device.blockIndex = serverEntry.index();
  user->devices.push_back(device);

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
      Users::createNewDeviceEntry(_trustchainId,
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
  device.blockIndex = serverEntry.index();
  user->devices.push_back(device);

  _entries.push_back(serverEntry);

  return {device, user->asTankerUser(), serverEntry};
}

TrustchainBuilder::ProvisionalUser TrustchainBuilder::makeProvisionalUser(
    std::string const& email)
{
  auto const secretProvisionalUser = SecretProvisionalUser{
      Tanker::Identity::TargetType::Email,
      email,
      Crypto::makeEncryptionKeyPair(),
      Crypto::makeEncryptionKeyPair(),
      Crypto::makeSignatureKeyPair(),
      Crypto::makeSignatureKeyPair(),
  };
  auto const publicProvisionalUser = PublicProvisionalUser{
      secretProvisionalUser.appSignatureKeyPair.publicKey,
      secretProvisionalUser.appEncryptionKeyPair.publicKey,
      secretProvisionalUser.tankerSignatureKeyPair.publicKey,
      secretProvisionalUser.tankerEncryptionKeyPair.publicKey,
  };
  auto const publicProvisionalIdentity = Identity::PublicProvisionalIdentity{
      _trustchainId,
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
    Tanker::SecretProvisionalUser const& provisionalUser,
    int authorDeviceIndex)
{
  auto const user = findUser(suserId).value();
  auto const& authorDevice = user.devices.at(authorDeviceIndex);

  auto const clientEntry = Users::createProvisionalIdentityClaimEntry(
      _trustchainId,
      authorDevice.id,
      authorDevice.keys.signatureKeyPair.privateKey,
      user.userId,
      provisionalUser,
      user.userKeys.back().keyPair);
  auto const serverEntry =
      clientToServerEntry(clientEntry, _entries.size() + 1);

  _entries.push_back(serverEntry);
  return serverEntry;
}

TrustchainBuilder::ResultGroup TrustchainBuilder::makeGroup(
    Device const& author,
    std::vector<User> const& users,
    std::vector<Tanker::PublicProvisionalUser> const& provisionalUsers)
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
      _trustchainId,
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
      serverEntry.index(),
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
    std::vector<Tanker::PublicProvisionalUser> const& provisionalUsers)
{
  auto const signatureKeyPair = Crypto::makeSignatureKeyPair();
  auto const encryptionKeyPair = Crypto::makeEncryptionKeyPair();

  std::vector<Tanker::Users::User> tusers;
  for (auto const& user : users)
    tusers.push_back(user.asTankerUser());

  auto const clientEntry = Groups::Manager::generateCreateGroupEntry(
      tusers,
      provisionalUsers,
      signatureKeyPair,
      encryptionKeyPair,
      _trustchainId,
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
      serverEntry.index(),
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
      _trustchainId,
      author.id,
      author.keys.signatureKeyPair.privateKey);

  auto const serverEntry =
      clientToServerEntry(clientEntry, _entries.size() + 1);
  _entries.push_back(serverEntry);

  group.tankerGroup.lastBlockHash = serverEntry.hash();
  group.tankerGroup.lastBlockIndex = serverEntry.index();

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
    std::vector<Tanker::PublicProvisionalUser> const& provisionalUsers)
{
  auto const newUsers = getOnlyNewMembers(group.members, users);

  std::vector<Tanker::Users::User> tusers;
  for (auto const& user : newUsers)
    tusers.push_back(user.asTankerUser());

  auto const clientEntry = Groups::Manager::generateAddUserToGroupEntry(
      tusers,
      provisionalUsers,
      group.tankerGroup,
      _trustchainId,
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
  group.tankerGroup.lastBlockIndex = serverEntry.index();

  std::transform(newUsers.begin(),
                 newUsers.end(),
                 std::back_inserter(group.members),
                 [](auto const& user) { return user.suserId; });

  // replace group in _groups
  _groups.erase(group);
  _groups.insert(group);

  return {group, serverEntry};
}

std::vector<ServerEntry> TrustchainBuilder::shareToDevice(
    Device const& sender,
    User const& receiver,
    ResourceId const& resourceId,
    Crypto::SymmetricKey const& key)
{
  if (!receiver.userKeys.empty())
    throw std::runtime_error("can't shareToDevice if the user has a user key");

  std::vector<ServerEntry> result;

  for (auto const& receiverDevice : receiver.devices)
  {
    auto const encryptedKey =
        Crypto::asymEncrypt<Crypto::EncryptedSymmetricKey>(
            key,
            sender.keys.encryptionKeyPair.privateKey,
            receiverDevice.keys.encryptionKeyPair.publicKey);

    auto const clientEntry = Users::createKeyPublishToDeviceEntry(
        _trustchainId,
        sender.id,
        sender.keys.signatureKeyPair.privateKey,
        encryptedKey,
        resourceId,
        receiverDevice.id);

    auto const serverEntry = clientToServerEntry(clientEntry);
    _entries.push_back(serverEntry);
    result.push_back(serverEntry);
  }
  return result;
}

ServerEntry TrustchainBuilder::shareToUser(Device const& sender,
                                           User const& receiver,
                                           ResourceId const& resourceId,
                                           Crypto::SymmetricKey const& key)
{
  if (receiver.userKeys.empty())
    throw std::runtime_error("can't shareToUser if the user has no user key");

  auto const receiverPublicKey = receiver.userKeys.back().keyPair.publicKey;

  auto const block =
      Share::makeKeyPublishToUser(_trustchainId,
                                  sender.id,
                                  sender.keys.signatureKeyPair.privateKey,
                                  receiverPublicKey,
                                  resourceId,
                                  key);

  auto entry = Serialization::deserialize<ServerEntry>(block);
  const_cast<std::uint64_t&>(entry.index()) = _entries.size() + 1;
  _entries.push_back(entry);

  return entry;
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
      _trustchainId, _entries.size() + 1, author, keyPublish, hash, signature);

  return _entries.back();
}

ServerEntry TrustchainBuilder::shareToProvisionalUser(
    Device const& sender,
    PublicProvisionalUser const& receiver,
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
      _trustchainId, _entries.size() + 1, author, keyPublish, hash, signature);

  return _entries.back();
}

ServerEntry TrustchainBuilder::revokeDevice1(Device const& sender,
                                             Device const& target,
                                             bool unsafe)
{
  auto const foundUser = std::find_if(
      _users.begin(), _users.end(), [sender, target](auto const user) {
        return std::find_if(user.devices.begin(),
                            user.devices.end(),
                            [sender](Device const& device) {
                              return device.asTankerDevice() ==
                                     sender.asTankerDevice();
                            }) != user.devices.end() &&
               std::find_if(user.devices.begin(),
                            user.devices.end(),
                            [target](Device const& device) {
                              return device.asTankerDevice() ==
                                     target.asTankerDevice();
                            }) != user.devices.end();
      });

  if (foundUser == _users.end() && !unsafe)
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
      _trustchainId, _entries.size() + 1, author, revocation, hash, signature);
  return _entries.back();
}

ServerEntry TrustchainBuilder::revokeDevice2(Device const& sender,
                                             Device const& target,
                                             User const& user,
                                             bool unsafe)
{
  auto const userHasDevices = user.findDevice(sender.id).has_value() &&
                              user.findDevice(target.id).has_value();

  if (!userHasDevices && !unsafe)
  {
    throw std::runtime_error(
        "TrustchainBuilder: cannot revoke a device from another user");
  }
  auto const newEncryptionKey = Crypto::makeEncryptionKeyPair();
  auto const tankerUser = user.asTankerUser();
  auto oldPublicEncryptionKey = Crypto::PublicEncryptionKey{};
  auto encryptedKeyForPreviousUserKey = Crypto::SealedPrivateEncryptionKey{};
  if (tankerUser.userKey)
  {
    oldPublicEncryptionKey = *tankerUser.userKey;
    encryptedKeyForPreviousUserKey = Crypto::sealEncrypt(
        user.userKeys.back().keyPair.privateKey, newEncryptionKey.publicKey);
  }

  DeviceRevocation::v2::SealedKeysForDevices userKeys;
  for (auto const& device : user.devices)
  {
    if (device.id != target.id)
    {
      Crypto::SealedPrivateEncryptionKey sealedEncryptedKey{
          Crypto::sealEncrypt(newEncryptionKey.privateKey,
                              device.keys.encryptionKeyPair.publicKey)};
      userKeys.emplace_back(device.id, sealedEncryptedKey);
    }
  }

  DeviceRevocation2 const revocation{target.id,
                                     newEncryptionKey.publicKey,
                                     encryptedKeyForPreviousUserKey,
                                     oldPublicEncryptionKey,
                                     userKeys};

  auto const nature = Nature::DeviceRevocation2;
  auto const author = static_cast<Crypto::Hash>(sender.id);
  auto const hash =
      computeHash(nature, author, Serialization::serialize(revocation));
  auto const signature =
      Crypto::sign(hash, sender.keys.signatureKeyPair.privateKey);
  _entries.emplace_back(
      _trustchainId, _entries.size() + 1, author, revocation, hash, signature);
  auto mutableUser = findMutableUser(user.suserId);
  mutableUser->userKeys.push_back(UserKey{newEncryptionKey, _entries.size()});
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

Tanker::Users::LocalUser::Ptr TrustchainBuilder::makeLocalUser(
    User const& user, Tanker::DataStore::ADatabase* conn) const
{
  auto result = AWAIT(Tanker::Users::LocalUser::open(
      Tanker::Identity::createIdentity(
          _trustchainId, _trustchainKeyPair.privateKey, user.userId),
      conn));
  for (auto const& userKey : user.userKeys)
    AWAIT_VOID(result->insertUserKey(userKey.keyPair));
  return result;
}

std::unique_ptr<Tanker::Users::ContactStore>
TrustchainBuilder::makeContactStoreWith(
    std::vector<std::string> const& suserIds,
    Tanker::DataStore::ADatabase* conn) const
{
  auto contactStore = std::make_unique<Tanker::Users::ContactStore>(conn);
  for (auto const& suserId : suserIds)
  {
    auto const optUser = findUser(suserId);
    if (!optUser)
    {
      throw Errors::AssertionError("makeContactStoreWith: no user named " +
                                   suserId);
    }
    AWAIT_VOID(contactStore->putUser(optUser->asTankerUser()));
  }
  return contactStore;
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
