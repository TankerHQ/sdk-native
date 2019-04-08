#pragma once

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Index.hpp>
#include <Tanker/Nature.hpp>
#include <Tanker/Types/UserId.hpp>

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

  Nature nature() const;
  std::vector<Index> makeIndexes() const;
};

bool operator==(KeyPublishToUserGroup const& l, KeyPublishToUserGroup const& r);
bool operator!=(KeyPublishToUserGroup const& l, KeyPublishToUserGroup const& r);

KeyPublishToUserGroup deserializeKeyPublishToUserGroup(
    gsl::span<uint8_t const> data);

std::uint8_t* to_serialized(std::uint8_t* it, KeyPublishToUserGroup const& dc);
std::size_t serialized_size(KeyPublishToUserGroup const& dc);
void to_json(nlohmann::json& j, KeyPublishToUserGroup const& dc);
}
