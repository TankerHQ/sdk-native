#include <Tanker/Actions/UserGroupAddition.hpp>

#include <Tanker/Actions/UserKeyPair.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Index.hpp>
#include <Tanker/Nature.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Types/UserId.hpp>
#include <Tanker/Identity/Delegation.hpp>

#include <gsl-lite.hpp>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <iterator>
#include <stdexcept>
#include <tuple>

namespace Tanker
{

Nature UserGroupAddition::nature() const
{
  return Nature::UserGroupAddition;
}

std::vector<Index> UserGroupAddition::makeIndexes() const
{
  return {};
}

std::vector<uint8_t> UserGroupAddition::signatureData() const
{
  std::vector<uint8_t> signatureData;
  signatureData.reserve(groupId.size() + previousGroupBlock.size() +
                        Serialization::detail::serialized_size(
                            encryptedGroupPrivateEncryptionKeysForUsers));
  signatureData.insert(signatureData.end(), groupId.begin(), groupId.end());
  signatureData.insert(signatureData.end(),
                       previousGroupBlock.begin(),
                       previousGroupBlock.end());
  for (auto const& elem : encryptedGroupPrivateEncryptionKeysForUsers)
  {
    signatureData.insert(signatureData.end(),
                         elem.publicUserEncryptionKey.begin(),
                         elem.publicUserEncryptionKey.end());
    signatureData.insert(signatureData.end(),
                         elem.encryptedGroupPrivateEncryptionKey.begin(),
                         elem.encryptedGroupPrivateEncryptionKey.end());
  }
  return signatureData;
}

bool operator==(UserGroupAddition const& l, UserGroupAddition const& r)
{
  return std::tie(l.groupId,
                  l.previousGroupBlock,
                  l.encryptedGroupPrivateEncryptionKeysForUsers,
                  l.selfSignatureWithCurrentKey) ==
         std::tie(r.groupId,
                  r.previousGroupBlock,
                  r.encryptedGroupPrivateEncryptionKeysForUsers,
                  r.selfSignatureWithCurrentKey);
}

bool operator!=(UserGroupAddition const& l, UserGroupAddition const& r)
{
  return !(l == r);
}

UserGroupAddition deserializeUserGroupAddition(gsl::span<uint8_t const> data)
{
  UserGroupAddition out{};

  Serialization::SerializedSource ss{data};

  out.groupId = Serialization::deserialize<GroupId>(ss);
  out.previousGroupBlock = Serialization::deserialize<Crypto::Hash>(ss);
  out.encryptedGroupPrivateEncryptionKeysForUsers =
      Serialization::deserialize<UserGroupAddition::GroupEncryptedKeys>(ss);
  out.selfSignatureWithCurrentKey =
      Serialization::deserialize<Crypto::Signature>(ss);

  if (!ss.eof())
    throw std::runtime_error("trailing garbage at end of UserGroupAddition");

  return out;
}

std::uint8_t* to_serialized(std::uint8_t* it, UserGroupAddition const& dc)
{
  it = Serialization::serialize(it, dc.groupId);
  it = Serialization::serialize(it, dc.previousGroupBlock);
  it = Serialization::serialize(it,
                                dc.encryptedGroupPrivateEncryptionKeysForUsers);
  return Serialization::serialize(it, dc.selfSignatureWithCurrentKey);
}

std::size_t serialized_size(UserGroupAddition const& dc)
{
  return dc.groupId.size() + dc.previousGroupBlock.size() +
         Serialization::serialized_size(
             dc.encryptedGroupPrivateEncryptionKeysForUsers) +
         dc.selfSignatureWithCurrentKey.size();
}

void to_json(nlohmann::json& j, UserGroupAddition const& dc)
{
  j["groupId"] = dc.groupId;
  j["previousGroupBlock"] = dc.previousGroupBlock;
  j["encryptedGroupPrivateEncryptionKeysForUsers"] =
      dc.encryptedGroupPrivateEncryptionKeysForUsers;
  j["selfSignatureWithCurrentKey"] = dc.selfSignatureWithCurrentKey;
}
}
