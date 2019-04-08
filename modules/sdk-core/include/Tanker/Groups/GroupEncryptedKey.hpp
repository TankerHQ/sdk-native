#pragma once

#include <Tanker/Crypto/Types.hpp>

#include <Tanker/Serialization/Serialization.hpp>
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
std::size_t serialized_size(GroupEncryptedKey const& keys);

bool operator==(GroupEncryptedKey const& lhs, GroupEncryptedKey const& rhs);

bool operator!=(GroupEncryptedKey const& lhs, GroupEncryptedKey const& rhs);

void to_json(nlohmann::json& j, GroupEncryptedKey const& keys);
}
