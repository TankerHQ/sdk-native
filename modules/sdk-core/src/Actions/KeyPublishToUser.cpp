#include <Tanker/Actions/KeyPublishToUser.hpp>

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
Nature KeyPublishToUser::nature() const
{
  return Nature::KeyPublishToUser;
}

std::vector<Index> KeyPublishToUser::makeIndexes() const
{
  return {};
}

bool operator==(KeyPublishToUser const& l, KeyPublishToUser const& r)
{
  return std::tie(l.recipientPublicEncryptionKey, l.mac, l.key) ==
         std::tie(r.recipientPublicEncryptionKey, r.mac, r.key);
}

bool operator!=(KeyPublishToUser const& l, KeyPublishToUser const& r)
{
  return !(l == r);
}

std::size_t serialized_size(KeyPublishToUser const& kp)
{
  return kp.recipientPublicEncryptionKey.size() + kp.mac.size() + kp.key.size();
}

KeyPublishToUser deserializeKeyPublishToUser(gsl::span<uint8_t const> data)
{
  KeyPublishToUser out;
  Serialization::SerializedSource ss{data};

  out.recipientPublicEncryptionKey =
      Serialization::deserialize<Crypto::Hash>(ss);
  out.mac = Serialization::deserialize<Crypto::Mac>(ss);
  out.key = Serialization::deserialize<Crypto::SealedSymmetricKey>(ss);

  if (!ss.eof())
    throw std::runtime_error("trailing garbage at end of KeyPublishToUser");

  return out;
}

void to_json(nlohmann::json& j, KeyPublishToUser const& kp)
{
  j["recipientPublicEncryptionKey"] = kp.recipientPublicEncryptionKey;
  j["mac"] = kp.mac;
  j["key"] = base64::encode(kp.key);
}
}
