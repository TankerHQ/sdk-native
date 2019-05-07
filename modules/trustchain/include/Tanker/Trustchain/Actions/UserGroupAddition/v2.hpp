#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Actions/UserGroupMember2.hpp>
#include <Tanker/Trustchain/Actions/UserGroupProvisionalMember2.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Json.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Serialization.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
#define TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_ADDITION2_ATTRIBUTES     \
  (groupId, GroupId), (previousGroupBlockHash, Crypto::Hash),         \
      (members, std::vector<UserGroupMember2>),                       \
      (provisionalMembers, std::vector<UserGroupProvisionalMember2>), \
      (selfSignature, Crypto::Signature)

class UserGroupAddition2
{
public:
  using Member = UserGroupMember2;
  using ProvisionalMember = UserGroupProvisionalMember2;

  TANKER_TRUSTCHAIN_ACTION_IMPLEMENTATION(
      UserGroupAddition2,
      TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_ADDITION2_ATTRIBUTES)

public:
  UserGroupAddition2(GroupId const&,
                     Crypto::Hash const&,
                     std::vector<Member> const&,
                     std::vector<ProvisionalMember> const&);

  static constexpr Nature nature();

  std::vector<std::uint8_t> signatureData() const;

  Crypto::Signature const& selfSign(Crypto::PrivateSignatureKey const&);

  friend void from_serialized(Serialization::SerializedSource&,
                              UserGroupAddition2&);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(UserGroupAddition2)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(UserGroupAddition2)

constexpr Nature UserGroupAddition2::nature()
{
  return Nature::UserGroupAddition2;
}
}
}
}
