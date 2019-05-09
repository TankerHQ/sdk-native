#include <Tanker/Trustchain/Actions/UserGroupAddition/v2.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
UserGroupAddition2::UserGroupAddition2(
    GroupId const& groupId,
    Crypto::Hash const& previousGroupBlockHash,
    std::vector<Member> const& members,
    std::vector<ProvisionalMember> const& provisionalMembers)
  : _groupId(groupId),
    _previousGroupBlockHash(previousGroupBlockHash),
    _members(members),
    _provisionalMembers(provisionalMembers)
{
}

std::vector<std::uint8_t> UserGroupAddition2::signatureData() const
{
  std::vector<std::uint8_t> signatureData(
      Crypto::Hash::arraySize + GroupId::arraySize +
      (Serialization::serialized_size(Member{}) * _members.size()) +
      (Serialization::serialized_size(ProvisionalMember{}) *
       _provisionalMembers.size()));

  auto it = Serialization::serialize(signatureData.data(), _groupId);
  it = Serialization::serialize(it, _previousGroupBlockHash);
  // loop over vector to avoid copying varint size
  for (auto const& elem : _members)
    it = Serialization::serialize(it, elem);
  for (auto const& elem : _provisionalMembers)
    it = Serialization::serialize(it, elem);
  return signatureData;
}

Crypto::Signature const& UserGroupAddition2::selfSign(
    Crypto::PrivateSignatureKey const& privateSignatureKey)
{
  auto const toSign = signatureData();

  return _selfSignature = Crypto::sign(toSign, privateSignatureKey);
}

TANKER_TRUSTCHAIN_ACTION_DEFINE_SERIALIZATION(
    UserGroupAddition2,
    TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_ADDITION2_ATTRIBUTES)

TANKER_TRUSTCHAIN_ACTION_DEFINE_TO_JSON(
    UserGroupAddition2,
    TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_ADDITION2_ATTRIBUTES)
}
}
}
