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

template <typename OutputIterator>
void to_serialized(OutputIterator it, GroupEncryptedKey const& key)
{
  Serialization::serialize(it, key.publicUserEncryptionKey);
  Serialization::serialize(it, key.encryptedGroupPrivateEncryptionKey);
}

std::size_t serialized_size(GroupEncryptedKey const& keys);

bool operator==(GroupEncryptedKey const& lhs, GroupEncryptedKey const& rhs);

bool operator!=(GroupEncryptedKey const& lhs, GroupEncryptedKey const& rhs);

void to_json(nlohmann::json& j, GroupEncryptedKey const& keys);
}
