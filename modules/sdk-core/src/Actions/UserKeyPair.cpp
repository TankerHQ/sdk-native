#include <Tanker/Actions/UserKeyPair.hpp>

#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Serialization/Varint.hpp>

#include <nlohmann/json.hpp>

#include <cstddef>
#include <tuple>

namespace Tanker
{
bool operator==(UserKeyPair const& l, UserKeyPair const& r)
{
  return std::tie(l.publicEncryptionKey, l.encryptedPrivateEncryptionKey) ==
         std::tie(r.publicEncryptionKey, r.encryptedPrivateEncryptionKey);
}

bool operator!=(UserKeyPair const& l, UserKeyPair const& r)
{
  return !(l == r);
}

void to_json(nlohmann::json& j, UserKeyPair const& uu)
{
  j["publicEncryptionKey"] = uu.publicEncryptionKey;
  j["encryptedPrivateEncryptionKey"] = uu.encryptedPrivateEncryptionKey;
}

std::uint8_t* to_serialized(std::uint8_t* it, UserKeyPair const& ukp)
{
  it = Serialization::serialize(it, ukp.publicEncryptionKey);
  return Serialization::serialize(it, ukp.encryptedPrivateEncryptionKey);
}

void from_serialized(Serialization::SerializedSource& ss, UserKeyPair& userKeys)
{
  userKeys.publicEncryptionKey =
      Serialization::deserialize<Crypto::PublicEncryptionKey>(ss);

  userKeys.encryptedPrivateEncryptionKey =
      Serialization::deserialize<Crypto::SealedPrivateEncryptionKey>(ss);
}
}
