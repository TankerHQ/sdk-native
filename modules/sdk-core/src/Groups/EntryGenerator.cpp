#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Groups/EntryGenerator.hpp>

#include <Tanker/Crypto/Crypto.hpp>

using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;
using namespace Tanker::Errors;

namespace Tanker::Groups
{
UserGroupCreation::v1::SealedPrivateEncryptionKeysForUsers
generateGroupKeysForUsers1(
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
    std::vector<Users::User> const& users)
{
  UserGroupCreation::v1::SealedPrivateEncryptionKeysForUsers keysForUsers;
  for (auto const& user : users)
  {
    if (!user.userKey())
      throw AssertionError("can't add a user without user key to a group");
    keysForUsers.emplace_back(
        *user.userKey(),
        Crypto::sealEncrypt(groupPrivateEncryptionKey, *user.userKey()));
  }
  return keysForUsers;
}

UserGroupCreation::v2::Members generateGroupKeysForUsers2(
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
    std::vector<Users::User> const& users)
{
  UserGroupCreation::v2::Members keysForUsers;
  for (auto const& user : users)
  {
    if (!user.userKey())
      throw AssertionError("cannot create group for users without a user key");

    keysForUsers.emplace_back(
        user.id(),
        *user.userKey(),
        Crypto::sealEncrypt(groupPrivateEncryptionKey, *user.userKey()));
  }
  return keysForUsers;
}

UserGroupCreation::v2::Members generateGroupKeysForUsers2(
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
    std::vector<RawUserGroupMember2> const& users)
{
  UserGroupCreation::v2::Members keysForUsers;
  for (auto const& user : users)
  {
    keysForUsers.emplace_back(
        user.userId,
        user.userPublicKey,
        Crypto::sealEncrypt(groupPrivateEncryptionKey, user.userPublicKey));
  }
  return keysForUsers;
}

UserGroupCreation::v2::ProvisionalMembers generateGroupKeysForProvisionalUsers2(
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
    std::vector<ProvisionalUsers::PublicUser> const& users)
{
  UserGroupCreation::v2::ProvisionalMembers keysForProvUsers;
  for (auto const& user : users)
  {
    auto const encryptedKeyOnce = Crypto::sealEncrypt(
        groupPrivateEncryptionKey, user.appEncryptionPublicKey());
    auto const encryptedKeyTwice =
        Crypto::sealEncrypt(encryptedKeyOnce, user.tankerEncryptionPublicKey());

    keysForProvUsers.emplace_back(user.appSignaturePublicKey(),
                                  user.tankerSignaturePublicKey(),
                                  encryptedKeyTwice);
  }
  return keysForProvUsers;
}

UserGroupCreation::v3::ProvisionalMembers generateGroupKeysForProvisionalUsers3(
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
    std::vector<ProvisionalUsers::PublicUser> const& users)
{
  UserGroupCreation::v3::ProvisionalMembers keysForProvUsers;
  for (auto const& user : users)
  {
    auto const encryptedKeyOnce = Crypto::sealEncrypt(
        groupPrivateEncryptionKey, user.appEncryptionPublicKey());
    auto const encryptedKeyTwice =
        Crypto::sealEncrypt(encryptedKeyOnce, user.tankerEncryptionPublicKey());

    keysForProvUsers.emplace_back(user.appSignaturePublicKey(),
                                  user.tankerSignaturePublicKey(),
                                  user.appEncryptionPublicKey(),
                                  user.tankerEncryptionPublicKey(),
                                  encryptedKeyTwice);
  }
  return keysForProvUsers;
}

UserGroupCreation::v3::ProvisionalMembers generateGroupKeysForProvisionalUsers3(
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
    std::vector<RawUserGroupProvisionalMember3> const& users)
{
  UserGroupCreation::v3::ProvisionalMembers keysForUsers;
  for (auto const& user : users)
  {
    auto const encryptedKeyOnce = Crypto::sealEncrypt(
        groupPrivateEncryptionKey, user.appPublicEncryptionKey);
    auto const encryptedKeyTwice =
        Crypto::sealEncrypt(encryptedKeyOnce, user.tankerPublicEncryptionKey);

    keysForUsers.emplace_back(user.appPublicSignatureKey,
                              user.tankerPublicSignatureKey,
                              user.appPublicEncryptionKey,
                              user.tankerPublicEncryptionKey,
                              encryptedKeyTwice);
  }
  return keysForUsers;
}

Trustchain::Actions::UserGroupCreation1 createUserGroupCreationV1Action(
    Crypto::SignatureKeyPair const& groupSignatureKeyPair,
    Crypto::PublicEncryptionKey const& groupPublicEncryptionKey,
    UserGroupCreation::v1::SealedPrivateEncryptionKeysForUsers const&
        sealedPrivateEncryptionKeysForUsers,
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey)
{
  auto const encryptedPrivateSignatureKey = Crypto::sealEncrypt(
      groupSignatureKeyPair.privateKey, groupPublicEncryptionKey);

  return UserGroupCreation::v1{trustchainId,
                               groupSignatureKeyPair.publicKey,
                               groupPublicEncryptionKey,
                               encryptedPrivateSignatureKey,
                               sealedPrivateEncryptionKeysForUsers,
                               static_cast<Crypto::Hash>(deviceId),
                               groupSignatureKeyPair.privateKey,
                               deviceSignatureKey};
}

Trustchain::Actions::UserGroupCreation2 createUserGroupCreationV2Action(
    Crypto::SignatureKeyPair const& groupSignatureKeyPair,
    Crypto::PublicEncryptionKey const& groupPublicEncryptionKey,
    UserGroupCreation::v2::Members const& groupMembers,
    UserGroupCreation::v2::ProvisionalMembers const& groupProvisionalMembers,
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey)
{
  auto const encryptedPrivateSignatureKey = Crypto::sealEncrypt(
      groupSignatureKeyPair.privateKey, groupPublicEncryptionKey);

  return UserGroupCreation::v2{trustchainId,
                               groupSignatureKeyPair.publicKey,
                               groupPublicEncryptionKey,
                               encryptedPrivateSignatureKey,
                               groupMembers,
                               groupProvisionalMembers,
                               static_cast<Crypto::Hash>(deviceId),
                               groupSignatureKeyPair.privateKey,
                               deviceSignatureKey};
}

Trustchain::Actions::UserGroupCreation3 createUserGroupCreationV3Action(
    Crypto::SignatureKeyPair const& groupSignatureKeyPair,
    Crypto::PublicEncryptionKey const& groupPublicEncryptionKey,
    UserGroupCreation::v2::Members const& groupMembers,
    UserGroupCreation::v3::ProvisionalMembers const& groupProvisionalMembers,
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey)
{
  auto const encryptedPrivateSignatureKey = Crypto::sealEncrypt(
      groupSignatureKeyPair.privateKey, groupPublicEncryptionKey);

  return UserGroupCreation::v3{
      trustchainId,
      groupSignatureKeyPair.publicKey,
      groupPublicEncryptionKey,
      encryptedPrivateSignatureKey,
      groupMembers,
      groupProvisionalMembers,
      static_cast<Crypto::Hash>(deviceId),
      groupSignatureKeyPair.privateKey,
      deviceSignatureKey,
  };
}

Trustchain::Actions::UserGroupAddition1 createUserGroupAdditionV1Action(
    Crypto::SignatureKeyPair const& groupSignatureKeyPair,
    Crypto::Hash const& previousGroupBlockHash,
    UserGroupAddition::v1::SealedPrivateEncryptionKeysForUsers const&
        sealedPrivateEncryptionKeysForUsers,
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey)
{
  GroupId const groupId{groupSignatureKeyPair.publicKey.base()};
  return UserGroupAddition::v1{
      trustchainId,
      groupId,
      previousGroupBlockHash,
      sealedPrivateEncryptionKeysForUsers,
      static_cast<Crypto::Hash>(deviceId),
      groupSignatureKeyPair.privateKey,
      deviceSignatureKey,
  };
}

Trustchain::Actions::UserGroupAddition2 createUserGroupAdditionV2Action(
    Crypto::SignatureKeyPair const& groupSignatureKeyPair,
    Crypto::Hash const& previousGroupBlockHash,
    std::vector<UserGroupAddition::v2::Member> const& members,
    std::vector<UserGroupAddition::v2::ProvisionalMember> const&
        provisionalMembers,
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey)
{
  GroupId const groupId{groupSignatureKeyPair.publicKey.base()};
  return UserGroupAddition::v2{
      trustchainId,
      groupId,
      previousGroupBlockHash,
      members,
      provisionalMembers,
      static_cast<Crypto::Hash>(deviceId),
      groupSignatureKeyPair.privateKey,
      deviceSignatureKey,
  };
}

Trustchain::Actions::UserGroupAddition3 createUserGroupAdditionV3Action(
    Crypto::SignatureKeyPair const& groupSignatureKeyPair,
    Crypto::Hash const& previousGroupBlockHash,
    std::vector<UserGroupAddition::v2::Member> const& members,
    std::vector<UserGroupAddition::v3::ProvisionalMember> const&
        provisionalMembers,
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey)
{
  GroupId const groupId{groupSignatureKeyPair.publicKey.base()};
  return UserGroupAddition::v3{
      trustchainId,
      groupId,
      previousGroupBlockHash,
      members,
      provisionalMembers,
      static_cast<Crypto::Hash>(deviceId),
      groupSignatureKeyPair.privateKey,
      deviceSignatureKey,
  };
}

KeyPublishToUserGroup createKeyPublishToGroupAction(
    Crypto::SealedSymmetricKey const& symKey,
    Crypto::SimpleResourceId const& resourceId,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey)
{
  return KeyPublishToUserGroup{
      trustchainId,
      recipientPublicEncryptionKey,
      resourceId,
      symKey,
      static_cast<Crypto::Hash>(deviceId),
      deviceSignatureKey,
  };
}
}
