#pragma once

#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Trustchain/Actions/UserGroupMember2.hpp>
#include <Tanker/Trustchain/Actions/UserGroupProvisionalMember3.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>

#include <utility>
#include <vector>

namespace Tanker::Trustchain::Actions
{
#define TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_ADDITION3_ATTRIBUTES                                       \
  (groupId, GroupId), (previousGroupBlockHash, Crypto::Hash), (members, std::vector<UserGroupMember2>), \
      (provisionalMembers, std::vector<UserGroupProvisionalMember3>), (selfSignature, Crypto::Signature)

class UserGroupAddition3
{
public:
  using Member = UserGroupMember2;
  using ProvisionalMember = UserGroupProvisionalMember3;

  TANKER_IMMUTABLE_ACTION_IMPLEMENTATION(UserGroupAddition3, TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_ADDITION3_ATTRIBUTES)

public:
  UserGroupAddition3(TrustchainId const& trustchainId,
                     GroupId const& groupId,
                     Crypto::Hash const& previousGroupBlockHash,
                     std::vector<Member> const& members,
                     std::vector<ProvisionalMember> const& provisionalMembers,
                     Crypto::Hash const& author,
                     Crypto::PrivateSignatureKey const& groupPrivateSignatureKey,
                     Crypto::PrivateSignatureKey const& devicePrivateSignatureKey);

  std::vector<std::uint8_t> signatureData() const;

private:
  friend void from_serialized(Serialization::SerializedSource&, UserGroupAddition3&);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(UserGroupAddition3)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(UserGroupAddition3)
}
