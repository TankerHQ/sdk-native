#include <Tanker/Actions/KeyPublishToUserGroup.hpp>

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Crypto/base64.hpp>
#include <Tanker/Index.hpp>
#include <Tanker/Nature.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <gsl-lite.hpp>
#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace Tanker
{
Nature KeyPublishToUserGroup::nature() const
{
  return Nature::KeyPublishToUserGroup;
}

std::vector<Index> KeyPublishToUserGroup::makeIndexes() const
{
  return {};
}

bool operator==(KeyPublishToUserGroup const& l, KeyPublishToUserGroup const& r)
{
  return std::tie(l.recipientPublicEncryptionKey, l.resourceId, l.key) ==
         std::tie(r.recipientPublicEncryptionKey, r.resourceId, r.key);
}

bool operator!=(KeyPublishToUserGroup const& l, KeyPublishToUserGroup const& r)
{
  return !(l == r);
}

KeyPublishToUserGroup deserializeKeyPublishToUserGroup(
    gsl::span<uint8_t const> data)
{
  KeyPublishToUserGroup out;
  Serialization::SerializedSource ss{data};

  out.recipientPublicEncryptionKey =
      Serialization::deserialize<Crypto::Hash>(ss);
  out.resourceId = Serialization::deserialize<Crypto::Mac>(ss);
  out.key = Serialization::deserialize<Crypto::SealedSymmetricKey>(ss);

  if (!ss.eof())
    throw std::runtime_error(
        "trailing garbage at end of KeyPublishToUserGroup");

  return out;
}

std::uint8_t* to_serialized(std::uint8_t* it, KeyPublishToUserGroup const& dc)
{
  it = Serialization::serialize(it, dc.recipientPublicEncryptionKey);
  it = Serialization::serialize(it, dc.resourceId);
  return Serialization::serialize(it, dc.key);
}

void to_json(nlohmann::json& j, KeyPublishToUserGroup const& kp)
{
  j["recipientPublicEncryptionKey"] = kp.recipientPublicEncryptionKey;
  j["resourceId"] = kp.resourceId;
  j["key"] = base64::encode(kp.key);
}
}
