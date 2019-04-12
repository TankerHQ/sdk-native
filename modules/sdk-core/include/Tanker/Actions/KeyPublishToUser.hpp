#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedSymmetricKey.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Index.hpp>
#include <Tanker/Nature.hpp>

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

std::uint8_t* to_serialized(std::uint8_t* it, KeyPublishToUser const& kp);

constexpr std::size_t serialized_size(KeyPublishToUser const& kp)
{
  return kp.recipientPublicEncryptionKey.size() + kp.mac.size() + kp.key.size();
}

void to_json(nlohmann::json& j, KeyPublishToUser const& kp);
}
