#pragma once

#include <Tanker/Crypto/Mac.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedSymmetricKey.hpp>
#include <Tanker/Index.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <gsl-lite.hpp>
#include <nlohmann/json_fwd.hpp>
#include <optional.hpp>

#include <cstddef>
#include <vector>

namespace Tanker
{
struct KeyPublishToUserGroup
{
  Crypto::PublicEncryptionKey recipientPublicEncryptionKey;
  Crypto::Mac resourceId;
  Crypto::SealedSymmetricKey key;

  Trustchain::Actions::Nature nature() const;
  std::vector<Index> makeIndexes() const;
};

bool operator==(KeyPublishToUserGroup const& l, KeyPublishToUserGroup const& r);
bool operator!=(KeyPublishToUserGroup const& l, KeyPublishToUserGroup const& r);

KeyPublishToUserGroup deserializeKeyPublishToUserGroup(
    gsl::span<uint8_t const> data);

std::uint8_t* to_serialized(std::uint8_t* it, KeyPublishToUserGroup const& dc);

constexpr std::size_t serialized_size(KeyPublishToUserGroup const& kp)
{
  return kp.recipientPublicEncryptionKey.size() + kp.resourceId.size() +
         kp.key.size();
}

void to_json(nlohmann::json& j, KeyPublishToUserGroup const& dc);
}
