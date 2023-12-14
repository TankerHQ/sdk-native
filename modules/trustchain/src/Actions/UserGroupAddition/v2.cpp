#include <Tanker/Trustchain/Actions/UserGroupAddition/v2.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Serialization.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
UserGroupAddition2::UserGroupAddition2(TrustchainId const& trustchainId,
                                       GroupId const& groupId,
                                       Crypto::Hash const& previousGroupBlockHash,
                                       std::vector<Member> const& members,
                                       std::vector<ProvisionalMember> const& provisionalMembers,
                                       Crypto::Hash const& author,
                                       Crypto::PrivateSignatureKey const& groupPrivateSignatureKey,
                                       Crypto::PrivateSignatureKey const& devicePrivateSignatureKey)
  : _trustchainId(trustchainId),
    _groupId(groupId),
    _previousGroupBlockHash(previousGroupBlockHash),
    _members(members),
    _provisionalMembers(provisionalMembers),
    _selfSignature(Crypto::sign(signatureData(), groupPrivateSignatureKey)),
    _author(author),
    _hash(computeHash()),
    _signature(Crypto::sign(_hash, devicePrivateSignatureKey))
{
}

std::vector<std::uint8_t> UserGroupAddition2::signatureData() const
{
  std::vector<std::uint8_t> signatureData(
      Crypto::Hash::arraySize + GroupId::arraySize + (Serialization::serialized_size(Member{}) * _members.size()) +
      (Serialization::serialized_size(ProvisionalMember{}) * _provisionalMembers.size()));

  auto it = Serialization::serialize(signatureData.data(), _groupId);
  it = Serialization::serialize(it, _previousGroupBlockHash);
  // loop over vector to avoid copying varint size
  for (auto const& elem : _members)
    it = Serialization::serialize(it, elem);
  for (auto const& elem : _provisionalMembers)
    it = Serialization::serialize(it, elem);
  return signatureData;
}

TANKER_TRUSTCHAIN_ACTION_DEFINE_METHODS(UserGroupAddition2, TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_ADDITION2_ATTRIBUTES)
}
}
}
