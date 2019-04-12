#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/Types.hpp>

#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Serialization/serialized_size.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
struct GroupEncryptedKey
{
  Crypto::PublicEncryptionKey publicUserEncryptionKey;
  Crypto::SealedPrivateEncryptionKey encryptedGroupPrivateEncryptionKey;
};

void from_serialized(Serialization::SerializedSource& ss,
                     GroupEncryptedKey& keys);

std::uint8_t* to_serialized(std::uint8_t* it, GroupEncryptedKey const& key);

bool operator==(GroupEncryptedKey const& lhs, GroupEncryptedKey const& rhs);

bool operator!=(GroupEncryptedKey const& lhs, GroupEncryptedKey const& rhs);

constexpr std::size_t serialized_size(GroupEncryptedKey const& keys)
{
  return Serialization::serialized_size(keys.publicUserEncryptionKey) +
         Serialization::serialized_size(
             keys.encryptedGroupPrivateEncryptionKey);
}

void to_json(nlohmann::json& j, GroupEncryptedKey const& keys);
}
