#include "TrustchainBuilder.hpp"

#include <Tanker/Entry.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Groups/GroupEncryptedKey.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Share.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Types/SUserId.hpp>

#include <Helpers/Await.hpp>

#include <algorithm>
#include <cstring>

using namespace Tanker::Trustchain::Actions;
using namespace Tanker::Trustchain;
using namespace Tanker;

TrustchainBuilder::TrustchainBuilder()
  : _trustchainKeyPair(Tanker::Crypto::makeSignatureKeyPair())
{
  Block block{};
  block.nature = Nature::TrustchainCreation;
  block.payload = Serialization::serialize(
      TrustchainCreation{_trustchainKeyPair.publicKey});
  block.trustchainId = TrustchainId(block.hash());
  _trustchainId = block.trustchainId;
  block.index = _blocks.size() + 1;
  _blocks.push_back(block);
}

Tanker::Device TrustchainBuilder::Device::asTankerDevice() const
{
  return Tanker::Device{keys.deviceId,
                        blockIndex,
                        nonstd::nullopt,
                        keys.signatureKeyPair.publicKey,
                        keys.encryptionKeyPair.publicKey,
                        false};
}

Tanker::User TrustchainBuilder::User::asTankerUser() const
{
  Tanker::User tankerUser{
      userId,
      userKeys.empty() ?
          nonstd::optional<Tanker::Crypto::PublicEncryptionKey>() :
          userKeys.back().keyPair.publicKey,
      std::vector<Tanker::Device>(devices.size())};

  std::transform(devices.begin(),
                 devices.end(),
                 tankerUser.devices.begin(),
                 [](auto const& device) { return device.asTankerDevice(); });

  return tankerUser;
}

Tanker::ExternalGroup TrustchainBuilder::Group::asExternalGroup() const
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

auto TrustchainBuilder::makeUser(std::string const& suserId) -> ResultUser
{
  return makeUser3(suserId);
}

auto TrustchainBuilder::makeUser1(std::string const& suserId) -> ResultUser
{
  if (getUser(suserId))
    throw Error::formatEx("{} already exists", suserId);

  Device device{
      {
          Tanker::Crypto::makeSignatureKeyPair(),
          Tanker::Crypto::makeEncryptionKeyPair(),
          {}, // deviceId will be filled in later in this function
      },
      {}, // delegation will be filled in later
      {}  // blockIndex will be filled in later
  };
  auto const daUserId = SUserId{suserId};
  User user{
      daUserId,
      obfuscateUserId(daUserId, _trustchainId),
      {device},
      {},
      _blocks.size() + 1,
  };
  auto const delegation =
      Identity::makeDelegation(user.userId, _trustchainKeyPair.privateKey);

  auto const preserializedBlock =
      BlockGenerator(_trustchainId, trustchainPrivateKey(), {})
          .addUser1(delegation,
                    device.keys.signatureKeyPair.publicKey,
                    device.keys.encryptionKeyPair.publicKey);
  auto block = Serialization::deserialize<Block>(preserializedBlock);
  block.index = _blocks.size() + 1;
  _blocks.push_back(block);

  user.devices[0].delegation = delegation;
  user.devices[0].keys.deviceId = DeviceId(block.hash());
  user.devices[0].blockIndex = block.index;
  _users.push_back(user);

  auto const entry = blockToServerEntry(block);

  return {user, entry};
}

auto TrustchainBuilder::makeUser3(std::string const& suserId) -> ResultUser
{
  if (getUser(suserId))
    throw Error::formatEx("{} already exists", suserId);

  Device device{
      {
          Tanker::Crypto::makeSignatureKeyPair(),
          Tanker::Crypto::makeEncryptionKeyPair(),
          {} // deviceId will be filled in later in this function
      },
      {}, // delegation will be filled in later
      {}  // blockIndex will be filled in later
  };
  auto const daUserId = SUserId{suserId};
  User user{
      daUserId,
      Tanker::obfuscateUserId(daUserId, _trustchainId),
      {device},
      {{Tanker::Crypto::makeEncryptionKeyPair(), _blocks.size() + 1}},
      _blocks.size() + 1,
  };

  auto const delegation =
      Identity::makeDelegation(user.userId, _trustchainKeyPair.privateKey);

  auto const preserializedBlock =
      BlockGenerator(_trustchainId, trustchainPrivateKey(), {})
          .addUser3(delegation,
                    device.keys.signatureKeyPair.publicKey,
                    device.keys.encryptionKeyPair.publicKey,
                    user.userKeys.back().keyPair);
  auto block = Serialization::deserialize<Block>(preserializedBlock);

  block.index = _blocks.size() + 1;
  _blocks.push_back(block);

  user.devices[0].keys.deviceId = DeviceId(block.hash());
  user.devices[0].delegation = delegation;
  user.devices[0].blockIndex = block.index;
  _users.push_back(user);

  auto const entry = blockToServerEntry(block);

  return {user, entry};
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
  auto& user = getMutableUser(suserId);

  Device device{
      {
          Tanker::Crypto::makeSignatureKeyPair(),
          Tanker::Crypto::makeEncryptionKeyPair(),
          {} // deviceId will be filled in later in this function
      },
      {}, // delegation will be filled in later
      {}  // blockIndex will be filled in later
  };

  // the device that will validate this device
  auto const& validatorDevice = user.devices.at(validatorDeviceIndex);

  auto const delegation = Identity::makeDelegation(
      user.userId, validatorDevice.keys.signatureKeyPair.privateKey);

  auto const preserializedBlock =
      BlockGenerator(_trustchainId,
                     validatorDevice.keys.signatureKeyPair.privateKey,
                     validatorDevice.keys.deviceId)
          .addDevice1(delegation,
                      device.keys.signatureKeyPair.publicKey,
                      device.keys.encryptionKeyPair.publicKey);
  auto block = Serialization::deserialize<Block>(preserializedBlock);
  block.index = _blocks.size() + 1;
  _blocks.push_back(block);

  device.keys.deviceId = DeviceId(block.hash());
  device.delegation = delegation;
  device.blockIndex = block.index;
  user.devices.push_back(device);

  auto const tankerUser = user.asTankerUser();
  auto const entry = blockToServerEntry(block);

  return {device, tankerUser, entry};
}

auto TrustchainBuilder::makeDevice3(std::string const& p,
                                    int validatorDeviceIndex) -> ResultDevice
{
  auto const suserId = SUserId{p};
  auto& user = getMutableUser(suserId);

  if (user.userKeys.empty()) // upgrading the user
  {
    user.userKeys.push_back(
        {Tanker::Crypto::makeEncryptionKeyPair(), _blocks.size() + 1});
  }

  Device device{
      {
          Tanker::Crypto::makeSignatureKeyPair(),
          Tanker::Crypto::makeEncryptionKeyPair(),
          {}, // deviceId will be filled in later in this function
      },
      {}, // delegation will be filled in later
      {}  // blockIndex will be filled in later
  };

  // the device that will validate this device
  auto const& validatorDevice = user.devices.at(validatorDeviceIndex);

  auto const delegation = Identity::makeDelegation(
      user.userId, validatorDevice.keys.signatureKeyPair.privateKey);
  auto const preserializedBlock =
      BlockGenerator(_trustchainId,
                     validatorDevice.keys.signatureKeyPair.privateKey,
                     validatorDevice.keys.deviceId)
          .addDevice3(delegation,
                      device.keys.signatureKeyPair.publicKey,
                      device.keys.encryptionKeyPair.publicKey,
                      user.userKeys.back().keyPair);
  auto block = Serialization::deserialize<Block>(preserializedBlock);
  block.index = _blocks.size() + 1;
  _blocks.push_back(block);

  device.keys.deviceId = DeviceId(block.hash());
  device.delegation = delegation;
  device.blockIndex = block.index;
  user.devices.push_back(device);

  auto const tankerUser = user.asTankerUser();
  auto const entry = blockToServerEntry(block);

  return {device, tankerUser, entry};
}

Tanker::SecretProvisionalUser TrustchainBuilder::makeProvisionalUser(
    std::string const& email)
{
  return Tanker::SecretProvisionalUser{
      Tanker::Identity::TargetType::Email,
      email,
      Crypto::makeEncryptionKeyPair(),
      Crypto::makeEncryptionKeyPair(),
      Crypto::makeSignatureKeyPair(),
      Crypto::makeSignatureKeyPair(),
  };
}

Tanker::PublicProvisionalUser TrustchainBuilder::toPublicProvisionalUser(
    Tanker::SecretProvisionalUser const& u) const
{
  return Tanker::PublicProvisionalUser{
      u.appSignatureKeyPair.publicKey,
      u.appEncryptionKeyPair.publicKey,
      u.tankerSignatureKeyPair.publicKey,
      u.tankerEncryptionKeyPair.publicKey,
  };
}

ServerEntry TrustchainBuilder::claimProvisionalIdentity(
    std::string const& suserId,
    Tanker::SecretProvisionalUser const& provisionalUser,
    int authorDeviceIndex)
{
  auto const user = getUser(suserId).value();
  auto const& authorDevice = user.devices.at(authorDeviceIndex);

  auto const preserializedBlock =
      BlockGenerator(_trustchainId,
                     authorDevice.keys.signatureKeyPair.privateKey,
                     authorDevice.keys.deviceId)
          .provisionalIdentityClaim(
              user.userId, provisionalUser, user.userKeys.back().keyPair);
  auto block = Serialization::deserialize<Block>(preserializedBlock);
  block.index = _blocks.size() + 1;
  _blocks.push_back(block);

  auto const entry = blockToServerEntry(block);
  return entry;
}

TrustchainBuilder::ResultGroup TrustchainBuilder::makeGroup(
    Device const& author,
    std::vector<User> const& users,
    std::vector<Tanker::SecretProvisionalUser> const& provisionalUsers)
{
  // TODO use makeGroup2
  return makeGroup1(author, users);
}

namespace
{
UserGroupCreation1::SealedPrivateEncryptionKeysForUsers
generateGroupKeysForUsers(
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
    std::vector<TrustchainBuilder::User> const& users)
{
  UserGroupCreation1::SealedPrivateEncryptionKeysForUsers keysForUsers;
  for (auto const& user : users)
  {
    if (user.userKeys.empty())
      throw std::runtime_error(
          "TrustchainBuilder: can't add a user without user key to a group");
    keysForUsers.emplace_back(
        user.userKeys.back().keyPair.publicKey,
        Crypto::sealEncrypt<Crypto::SealedPrivateEncryptionKey>(
            groupPrivateEncryptionKey, user.userKeys.back().keyPair.publicKey));
  }
  return keysForUsers;
}

UserGroupCreation2::UserGroupMembers generateGroupKeysForUsers2(
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
    std::vector<TrustchainBuilder::User> const& users)
{
  UserGroupCreation2::UserGroupMembers keysForUsers;
  for (auto const& user : users)
  {
    if (user.userKeys.empty())
      throw std::runtime_error(
          "TrustchainBuilder: can't add a user without user key to a group");
    keysForUsers.emplace_back(
        user.userId,
        user.userKeys.back().keyPair.publicKey,
        Crypto::sealEncrypt<Crypto::SealedPrivateEncryptionKey>(
            groupPrivateEncryptionKey, user.userKeys.back().keyPair.publicKey));
  }
  return keysForUsers;
}

UserGroupCreation2::UserGroupProvisionalMembers
generateGroupKeysForProvisionalUsers(
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
    std::vector<Tanker::SecretProvisionalUser> const& users)
{
  UserGroupCreation2::UserGroupProvisionalMembers keysForUsers;
  for (auto const& user : users)
  {
    auto const encryptedKeyOnce = Crypto::sealEncrypt(
        groupPrivateEncryptionKey, user.appEncryptionKeyPair.publicKey);
    auto const encryptedKeyTwice =
        Crypto::sealEncrypt<Crypto::TwoTimesSealedPrivateEncryptionKey>(
            encryptedKeyOnce, user.tankerEncryptionKeyPair.publicKey);

    keysForUsers.emplace_back(user.appSignatureKeyPair.publicKey,
                              user.tankerSignatureKeyPair.publicKey,
                              encryptedKeyTwice);
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

  auto const preserializedBlock =
      BlockGenerator(_trustchainId,
                     author.keys.signatureKeyPair.privateKey,
                     author.keys.deviceId)
          .userGroupCreation(
              signatureKeyPair, encryptionKeyPair.publicKey, keysForUsers);

  auto block = Serialization::deserialize<Block>(preserializedBlock);
  block.index = _blocks.size() + 1;
  _blocks.push_back(block);

  auto const entry = blockToServerEntry(block);

  Tanker::Group tgroup{
      GroupId{signatureKeyPair.publicKey},
      signatureKeyPair,
      encryptionKeyPair,
      entry.hash(),
      block.index,
  };

  std::vector<SUserId> members;
  for (auto const& user : users)
    members.push_back(user.suserId);

  auto const encryptedPrivateSignatureKey = entry.action()
                                                .get<UserGroupCreation>()
                                                .get<UserGroupCreation1>()
                                                .sealedPrivateSignatureKey();
  Group group{tgroup, encryptedPrivateSignatureKey, members};

  _groups.insert(group);

  return {group, entry};
}

TrustchainBuilder::ResultGroup TrustchainBuilder::makeGroup2(
    Device const& author,
    std::vector<User> const& users,
    std::vector<Tanker::SecretProvisionalUser> const& provisionalUsers)
{
  auto const signatureKeyPair = Crypto::makeSignatureKeyPair();
  auto const encryptionKeyPair = Crypto::makeEncryptionKeyPair();
  auto const keysForUsers =
      generateGroupKeysForUsers2(encryptionKeyPair.privateKey, users);
  auto const keysForProvisionalUsers = generateGroupKeysForProvisionalUsers(
      encryptionKeyPair.privateKey, provisionalUsers);

  auto const preserializedBlock =
      BlockGenerator(_trustchainId,
                     author.keys.signatureKeyPair.privateKey,
                     author.keys.deviceId)
          .userGroupCreation2(signatureKeyPair,
                              encryptionKeyPair.publicKey,
                              keysForUsers,
                              keysForProvisionalUsers);

  auto block = Serialization::deserialize<Block>(preserializedBlock);
  block.index = _blocks.size() + 1;
  _blocks.push_back(block);

  auto const entry = blockToServerEntry(block);

  Tanker::Group tgroup{
      GroupId{signatureKeyPair.publicKey},
      signatureKeyPair,
      encryptionKeyPair,
      entry.hash(),
      block.index,
  };

  std::vector<SUserId> members;
  for (auto const& user : users)
    members.push_back(user.suserId);

  auto const encryptedPrivateSignatureKey = entry.action()
                                                .get<UserGroupCreation>()
                                                .get<UserGroupCreation2>()
                                                .sealedPrivateSignatureKey();
  Group group{tgroup, encryptedPrivateSignatureKey, members};

  _groups.insert(group);

  return {group, entry};
}

TrustchainBuilder::ResultGroup TrustchainBuilder::addUserToGroup(
    Device const& author, Group group, std::vector<User> const& users)
{
  auto const newUsers = getOnlyNewMembers(group.members, users);

  auto const keysForUsers = generateGroupKeysForUsers(
      group.tankerGroup.encryptionKeyPair.privateKey, newUsers);

  auto const preserializedBlock =
      BlockGenerator(_trustchainId,
                     author.keys.signatureKeyPair.privateKey,
                     author.keys.deviceId)
          .userGroupAddition(group.tankerGroup.signatureKeyPair,
                             group.tankerGroup.lastBlockHash,
                             keysForUsers);

  auto block = Serialization::deserialize<Block>(preserializedBlock);
  block.index = _blocks.size() + 1;
  _blocks.push_back(block);
  auto const entry = blockToServerEntry(block);

  group.tankerGroup.lastBlockHash = entry.hash();
  group.tankerGroup.lastBlockIndex = entry.index();

  std::transform(newUsers.begin(),
                 newUsers.end(),
                 std::back_inserter(group.members),
                 [](auto const& user) { return user.suserId; });

  // replace group in _groups
  _groups.erase(group);
  _groups.insert(group);

  return {group, entry};
}

TrustchainBuilder::ResultGroup TrustchainBuilder::addUserToGroup2(
    Device const& author,
    Group group,
    std::vector<User> const& users,
    std::vector<Tanker::SecretProvisionalUser> const& provisionalUsers)
{
  auto const newUsers = getOnlyNewMembers(group.members, users);

  auto const keysForUsers = generateGroupKeysForUsers2(
      group.tankerGroup.encryptionKeyPair.privateKey, newUsers);

  auto const keysForProvisionalUsers = generateGroupKeysForProvisionalUsers(
      group.tankerGroup.encryptionKeyPair.privateKey, provisionalUsers);

  auto const preserializedBlock =
      BlockGenerator(_trustchainId,
                     author.keys.signatureKeyPair.privateKey,
                     author.keys.deviceId)
          .userGroupAddition2(group.tankerGroup.signatureKeyPair,
                              group.tankerGroup.lastBlockHash,
                              keysForUsers,
                              keysForProvisionalUsers);

  auto block = Serialization::deserialize<Block>(preserializedBlock);
  block.index = _blocks.size() + 1;
  _blocks.push_back(block);
  auto const entry = blockToServerEntry(block);

  group.tankerGroup.lastBlockHash = entry.hash();
  group.tankerGroup.lastBlockIndex = entry.index();

  std::transform(newUsers.begin(),
                 newUsers.end(),
                 std::back_inserter(group.members),
                 [](auto const& user) { return user.suserId; });

  // replace group in _groups
  _groups.erase(group);
  _groups.insert(group);

  return {group, entry};
}

std::vector<Tanker::Block> TrustchainBuilder::shareToDevice(
    Device const& sender,
    User const& receiver,
    ResourceId const& resourceId,
    Crypto::SymmetricKey const& key)
{
  if (!receiver.userKeys.empty())
    throw std::runtime_error("can't shareToDevice if the user has a user key");

  std::vector<Tanker::Block> result;

  for (auto const& receiverDevice : receiver.devices)
  {
    auto const encryptedKey =
        Crypto::asymEncrypt<Crypto::EncryptedSymmetricKey>(
            key,
            sender.keys.encryptionKeyPair.privateKey,
            receiverDevice.keys.encryptionKeyPair.publicKey);

    auto const block =
        BlockGenerator(_trustchainId,
                       sender.keys.signatureKeyPair.privateKey,
                       sender.keys.deviceId)
            .keyPublish(encryptedKey, resourceId, receiverDevice.keys.deviceId);

    auto deserializedBlock = Serialization::deserialize<Block>(block);
    deserializedBlock.index = _blocks.size() + 1;
    _blocks.push_back(deserializedBlock);
    result.push_back(deserializedBlock);
  }
  return result;
}

Tanker::Block TrustchainBuilder::shareToUser(Device const& sender,
                                             User const& receiver,
                                             ResourceId const& resourceId,
                                             Crypto::SymmetricKey const& key)
{
  if (receiver.userKeys.empty())
    throw std::runtime_error("can't shareToUser if the user has no user key");

  auto const receiverPublicKey = receiver.userKeys.back().keyPair.publicKey;

  auto const block = Share::makeKeyPublishToUser(
      BlockGenerator(_trustchainId,
                     sender.keys.signatureKeyPair.privateKey,
                     sender.keys.deviceId),
      receiverPublicKey,
      resourceId,
      key);

  auto deserializedBlock = Serialization::deserialize<Block>(block);
  deserializedBlock.index = _blocks.size() + 1;
  _blocks.push_back(deserializedBlock);

  return deserializedBlock;
}

Tanker::Block TrustchainBuilder::shareToUserGroup(
    Device const& sender,
    Group const& receiver,
    ResourceId const& resourceId,
    Crypto::SymmetricKey const& key)
{
  auto const receiverPublicKey =
      receiver.tankerGroup.encryptionKeyPair.publicKey;

  auto const encryptedKey =
      Crypto::sealEncrypt<Crypto::SealedSymmetricKey>(key, receiverPublicKey);

  KeyPublishToUserGroup keyPublish{receiverPublicKey, resourceId, encryptedKey};

  Block block;
  block.trustchainId = _trustchainId;
  block.author = Crypto::Hash{sender.keys.deviceId};
  block.nature = Nature::KeyPublishToUserGroup;
  block.payload = Serialization::serialize(keyPublish);
  block.signature =
      Crypto::sign(block.hash(), sender.keys.signatureKeyPair.privateKey);

  block.index = _blocks.size() + 1;
  _blocks.push_back(block);

  return block;
}

Block TrustchainBuilder::shareToProvisionalUser(
    Device const& sender,
    SecretProvisionalUser const& receiver,
    ResourceId const& resourceId,
    Crypto::SymmetricKey const& key)
{
  auto const encryptedKeyOnce =
      Crypto::sealEncrypt(key, receiver.appEncryptionKeyPair.publicKey);
  auto const encryptedKeyTwice =
      Crypto::sealEncrypt<Crypto::TwoTimesSealedSymmetricKey>(
          encryptedKeyOnce, receiver.tankerEncryptionKeyPair.publicKey);

  KeyPublishToProvisionalUser keyPublish{
      receiver.appSignatureKeyPair.publicKey,
      resourceId,
      receiver.tankerSignatureKeyPair.publicKey,
      encryptedKeyTwice};

  Block block;
  block.trustchainId = _trustchainId;
  block.author = Crypto::Hash{sender.keys.deviceId};
  block.nature = Nature::KeyPublishToProvisionalUser;
  block.payload = Serialization::serialize(keyPublish);
  block.signature =
      Crypto::sign(block.hash(), sender.keys.signatureKeyPair.privateKey);

  block.index = _blocks.size() + 1;
  _blocks.push_back(block);

  return block;
}

Tanker::Block TrustchainBuilder::revokeDevice1(Device const& sender,
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

  auto const revocation = DeviceRevocation1{target.keys.deviceId};

  Block block;
  block.trustchainId = _trustchainId;
  block.author = Crypto::Hash{sender.keys.deviceId};
  block.nature = Nature::DeviceRevocation;
  block.payload = Serialization::serialize(revocation);
  block.signature =
      Crypto::sign(block.hash(), sender.keys.signatureKeyPair.privateKey);

  block.index = _blocks.size() + 1;
  _blocks.push_back(block);

  return block;
}

Tanker::Block TrustchainBuilder::revokeDevice2(Device const& sender,
                                               Device const& target,
                                               User const& user,
                                               bool unsafe)
{
  auto const userHasDevices =
      std::find_if(user.devices.begin(),
                   user.devices.end(),
                   [sender](Device const& device) {
                     return device.asTankerDevice() == sender.asTankerDevice();
                   }) != user.devices.end() &&
      std::find_if(user.devices.begin(),
                   user.devices.end(),
                   [target](Device const& device) {
                     return device.asTankerDevice() == target.asTankerDevice();
                   }) != user.devices.end();

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
    encryptedKeyForPreviousUserKey =
        Crypto::sealEncrypt<Crypto::SealedPrivateEncryptionKey>(
            user.userKeys.back().keyPair.privateKey,
            newEncryptionKey.publicKey);
  }

  DeviceRevocation::v2::SealedKeysForDevices userKeys;
  for (auto const& device : user.devices)
  {
    if (device.keys.deviceId != target.keys.deviceId)
    {
      Crypto::SealedPrivateEncryptionKey sealedEncryptedKey{
          Crypto::sealEncrypt(newEncryptionKey.privateKey,
                              device.keys.encryptionKeyPair.publicKey)};
      userKeys.emplace_back(device.keys.deviceId, sealedEncryptedKey);
    }
  }

  DeviceRevocation2 const revocation{target.keys.deviceId,
                                     newEncryptionKey.publicKey,
                                     encryptedKeyForPreviousUserKey,
                                     oldPublicEncryptionKey,
                                     userKeys};

  Block block;
  block.trustchainId = _trustchainId;
  block.author = Crypto::Hash{sender.keys.deviceId};
  block.nature = Nature::DeviceRevocation2;
  block.payload = Serialization::serialize(revocation);
  block.signature =
      Crypto::sign(block.hash(), sender.keys.signatureKeyPair.privateKey);

  block.index = _blocks.size() + 1;
  _blocks.push_back(block);

  return block;
}

nonstd::optional<TrustchainBuilder::User> TrustchainBuilder::getUser(
    std::string const& suserId) const
{
  try
  {
    return const_cast<TrustchainBuilder*>(this)->getMutableUser(
        SUserId{suserId});
  }
  catch (...)
  {
    return nonstd::nullopt;
  }
}

TrustchainBuilder::User& TrustchainBuilder::getMutableUser(
    SUserId const& suserId)
{
  auto const it =
      std::find_if(_users.begin(), _users.end(), [&](auto const& user) {
        return user.suserId == suserId;
      });
  if (it == _users.end())
    throw Error::formatEx("user {} not found", suserId);
  return *it;
}

Tanker::BlockGenerator TrustchainBuilder::makeBlockGenerator(
    TrustchainBuilder::Device const& device) const
{
  return Tanker::BlockGenerator(_trustchainId,
                                device.keys.signatureKeyPair.privateKey,
                                device.keys.deviceId);
}

std::unique_ptr<Tanker::UserKeyStore> TrustchainBuilder::makeUserKeyStore(
    User const& user, Tanker::DataStore::ADatabase* conn) const
{
  auto result = std::make_unique<Tanker::UserKeyStore>(conn);
  for (auto const& userKey : user.userKeys)
    AWAIT_VOID(result->putPrivateKey(userKey.keyPair.publicKey,
                                     userKey.keyPair.privateKey));
  return result;
}

std::unique_ptr<Tanker::ContactStore> TrustchainBuilder::makeContactStoreWith(
    std::vector<std::string> const& suserIds,
    Tanker::DataStore::ADatabase* conn) const
{
  auto contactStore = std::make_unique<Tanker::ContactStore>(conn);
  for (auto const& suserId : suserIds)
  {
    auto const optUser = getUser(suserId);
    if (!optUser)
      throw std::runtime_error("makeContactStoreWith: no user named " +
                               suserId);
    AWAIT_VOID(contactStore->putUser(optUser->asTankerUser()));
  }
  return contactStore;
}

std::unique_ptr<Tanker::ProvisionalUserKeysStore>
TrustchainBuilder::makeProvisionalUserKeysStoreWith(
    std::vector<Tanker::SecretProvisionalUser> const& provisionalUsers,
    Tanker::DataStore::ADatabase* conn) const
{
  auto provisionalUserKeysStore =
      std::make_unique<Tanker::ProvisionalUserKeysStore>(conn);
  for (auto const& provisionalUser : provisionalUsers)
  {
    AWAIT_VOID(provisionalUserKeysStore->putProvisionalUserKeys(
        provisionalUser.appSignatureKeyPair.publicKey,
        provisionalUser.tankerSignatureKeyPair.publicKey,
        {
            provisionalUser.appEncryptionKeyPair,
            provisionalUser.tankerEncryptionKeyPair,
        }));
  }
  return provisionalUserKeysStore;
}

std::unique_ptr<Tanker::GroupStore> TrustchainBuilder::makeGroupStore(
    TrustchainBuilder::User const& user,
    Tanker::DataStore::ADatabase* conn) const
{
  auto result = std::make_unique<Tanker::GroupStore>(conn);
  for (auto const& group : _groups)
  {
    if (std::find(group.members.begin(), group.members.end(), user.suserId) !=
        group.members.end())
      AWAIT_VOID(result->put(group.tankerGroup));
    else
      AWAIT_VOID(result->put(group.asExternalGroup()));
  }
  return result;
}

std::vector<Block> const& TrustchainBuilder::blocks() const
{
  return _blocks;
}

std::vector<TrustchainBuilder::Group> TrustchainBuilder::groups() const
{
  return std::vector<Group>(_groups.begin(), _groups.end());
}

std::vector<TrustchainBuilder::User> const& TrustchainBuilder::users() const
{
  return _users;
}
