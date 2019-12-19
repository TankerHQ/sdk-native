#include <Tanker/Groups/EntryGenerator.hpp>

#include <Tanker/Trustchain/Action.hpp>

using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

namespace Tanker::Groups
{
Trustchain::ClientEntry createUserGroupAdditionV1Entry(
    Crypto::SignatureKeyPair const& groupSignatureKeyPair,
    Crypto::Hash const& previousGroupBlockHash,
    UserGroupAddition::v1::SealedPrivateEncryptionKeysForUsers const&
        sealedPrivateEncryptionKeysForUsers,
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey)
{
  Trustchain::GroupId const groupId{groupSignatureKeyPair.publicKey.base()};
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
  Trustchain::GroupId const groupId{groupSignatureKeyPair.publicKey.base()};
  UserGroupAddition::v2 uga{
      groupId, previousGroupBlockHash, members, provisionalMembers};
  uga.selfSign(groupSignatureKeyPair.privateKey);

  return ClientEntry::create(trustchainId,
                             static_cast<Crypto::Hash>(deviceId),
                             uga,
                             deviceSignatureKey);
}
}
