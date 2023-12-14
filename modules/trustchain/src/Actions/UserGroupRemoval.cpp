#include <Tanker/Trustchain/Actions/UserGroupRemoval.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Serialization.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>

namespace Tanker::Trustchain::Actions
{
UserGroupRemoval::UserGroupRemoval(TrustchainId const& trustchainId,
                                   GroupId const& groupId,
                                   std::vector<UserId> membersToRemove,
                                   std::vector<ProvisionalUserId> provisionalMembersToRemove,
                                   DeviceId const& author,
                                   Crypto::PrivateSignatureKey const& groupPrivateSignatureKey,
                                   Crypto::PrivateSignatureKey const& devicePrivateSignatureKey)
  : _trustchainId(trustchainId),
    _groupId(groupId),
    _membersToRemove(std::move(membersToRemove)),
    _provisionalMembersToRemove(std::move(provisionalMembersToRemove)),
    _selfSignatureWithCurrentKey(Crypto::sign(signatureData(author), groupPrivateSignatureKey)),
    _author(author),
    _hash(computeHash()),
    _signature(Crypto::sign(_hash, devicePrivateSignatureKey))
{
}

namespace
{
constexpr std::string_view userGroupRemovalSignaturePrefix = "UserGroupRemoval Signature";
}

std::vector<std::uint8_t> UserGroupRemoval::signatureData(DeviceId const& authorId) const
{
  std::vector<std::uint8_t> signatureData(
      userGroupRemovalSignaturePrefix.size() + DeviceId::arraySize + sizeof(uint32_t) + GroupId::arraySize +
      _membersToRemove.size() * UserId::arraySize + sizeof(uint32_t) +
      _provisionalMembersToRemove.size() * (Crypto::PublicSignatureKey::arraySize * 2));

  auto it =
      std::copy(userGroupRemovalSignaturePrefix.begin(), userGroupRemovalSignaturePrefix.end(), signatureData.data());
  it = std::copy(authorId.begin(), authorId.end(), it);
  it = std::copy(_groupId.begin(), _groupId.end(), it);

  it = Serialization::serialize<uint32_t>(it, _membersToRemove.size());
  for (auto const& elem : _membersToRemove)
    it = Serialization::serialize(it, elem);

  it = Serialization::serialize<uint32_t>(it, _provisionalMembersToRemove.size());
  for (auto const& elem : _provisionalMembersToRemove)
    it = Serialization::serialize(it, elem);

  return signatureData;
}

TANKER_TRUSTCHAIN_ACTION_DEFINE_METHODS(UserGroupRemoval, TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_REMOVAL_ATTRIBUTES)
}
