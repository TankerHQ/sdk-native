#include <Tanker/Groups/EntryGenerator.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Trustchain/Action.hpp>

using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

namespace Tanker::Groups
{
Trustchain::Actions::UserGroupCreation1 createUserGroupCreationV1Entry(
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

Trustchain::Actions::UserGroupCreation2 createUserGroupCreationV2Entry(
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

  return UserGroupCreation::v2{
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

Trustchain::Actions::UserGroupAddition1 createUserGroupAdditionV1Entry(
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

Trustchain::Actions::UserGroupAddition2 createUserGroupAdditionV2Entry(
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

KeyPublishToUserGroup createKeyPublishToGroupEntry(
    Crypto::SealedSymmetricKey const& symKey,
    ResourceId const& resourceId,
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
