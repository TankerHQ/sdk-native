#pragma once

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Index.hpp>
#include <Tanker/Nature.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <gsl-lite.hpp>
#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace Tanker
{
struct KeyPublishToUser
{
  Crypto::PublicEncryptionKey recipientPublicEncryptionKey;
  Crypto::Mac mac;
  Crypto::SealedSymmetricKey key;

  Nature nature() const;
  std::vector<Index> makeIndexes() const;
};

bool operator==(KeyPublishToUser const& l, KeyPublishToUser const& r);
bool operator!=(KeyPublishToUser const& l, KeyPublishToUser const& r);

KeyPublishToUser deserializeKeyPublishToUser(gsl::span<uint8_t const> data);

template <typename OutputIterator>
void to_serialized(OutputIterator it, KeyPublishToUser const& kp)
{
  Serialization::serialize(it, kp.recipientPublicEncryptionKey);
  Serialization::serialize(it, kp.mac);
  Serialization::serialize(it, kp.key);
}

std::size_t serialized_size(KeyPublishToUser const& kp);

void to_json(nlohmann::json& j, KeyPublishToUser const& kp);
}
