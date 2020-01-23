#include <Tanker/Groups/EntryGenerator.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Trustchain/Action.hpp>

using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

namespace Tanker::Groups
{
ClientEntry createUserGroupCreationV1Entry(
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

  UserGroupCreation::v1 ugc{groupSignatureKeyPair.publicKey,
                            groupPublicEncryptionKey,
                            encryptedPrivateSignatureKey,
                            sealedPrivateEncryptionKeysForUsers};
  ugc.selfSign(groupSignatureKeyPair.privateKey);
  return ClientEntry::create(trustchainId,
                             static_cast<Crypto::Hash>(deviceId),
                             ugc,
                             deviceSignatureKey);
}

ClientEntry createUserGroupCreationV2Entry(
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

  UserGroupCreation::v2 ugc{groupSignatureKeyPair.publicKey,
                            groupPublicEncryptionKey,
                            encryptedPrivateSignatureKey,
                            groupMembers,
                            groupProvisionalMembers};
  ugc.selfSign(groupSignatureKeyPair.privateKey);
  return ClientEntry::create(trustchainId,
                             static_cast<Crypto::Hash>(deviceId),
                             ugc,
                             deviceSignatureKey);
}

ClientEntry createUserGroupAdditionV1Entry(
    Crypto::SignatureKeyPair const& groupSignatureKeyPair,
    Crypto::Hash const& previousGroupBlockHash,
    UserGroupAddition::v1::SealedPrivateEncryptionKeysForUsers const&
        sealedPrivateEncryptionKeysForUsers,
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey)
{
  GroupId const groupId{groupSignatureKeyPair.publicKey.base()};
  UserGroupAddition::v1 uga{
      groupId, previousGroupBlockHash, sealedPrivateEncryptionKeysForUsers};
  uga.selfSign(groupSignatureKeyPair.privateKey);

  return ClientEntry::create(trustchainId,
                             static_cast<Crypto::Hash>(deviceId),
                             uga,
                             deviceSignatureKey);
}

ClientEntry createUserGroupAdditionV2Entry(
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
  UserGroupAddition::v2 uga{
      groupId, previousGroupBlockHash, members, provisionalMembers};
  uga.selfSign(groupSignatureKeyPair.privateKey);

  return ClientEntry::create(trustchainId,
                             static_cast<Crypto::Hash>(deviceId),
                             uga,
                             deviceSignatureKey);
}

ClientEntry createKeyPublishToGroupEntry(
    Crypto::SealedSymmetricKey const& symKey,
    ResourceId const& resourceId,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey)
{
  KeyPublishToUserGroup kp{recipientPublicEncryptionKey, resourceId, symKey};

  return ClientEntry::create(trustchainId,
                             static_cast<Crypto::Hash>(deviceId),
                             kp,
                             deviceSignatureKey);
}
}
