#include <Tanker/Actions/KeyPublishToUser.hpp>

#include <Tanker/Index.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <gsl-lite.hpp>
#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

using Tanker::Trustchain::Actions::Nature;

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

std::uint8_t* to_serialized(std::uint8_t* it, KeyPublishToUser const& kp)
{
  it = Serialization::serialize(it, kp.recipientPublicEncryptionKey);
  it = Serialization::serialize(it, kp.mac);
  return Serialization::serialize(it, kp.key);
}

KeyPublishToUser deserializeKeyPublishToUser(gsl::span<uint8_t const> data)
{
  KeyPublishToUser out;
  Serialization::SerializedSource ss{data};

  out.recipientPublicEncryptionKey =
      Serialization::deserialize<Crypto::PublicEncryptionKey>(ss);
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
  j["key"] = cppcodec::base64_rfc4648::encode(kp.key);
}
}
