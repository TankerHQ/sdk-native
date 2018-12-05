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

template <typename OutputIterator>
void to_serialized(OutputIterator it, KeyPublishToUserGroup const& dc)
{
  Serialization::serialize(it, dc.recipientPublicEncryptionKey);
  Serialization::serialize(it, dc.resourceId);
  Serialization::serialize(it, dc.key);
}

std::size_t serialized_size(KeyPublishToUserGroup const& dc);
void to_json(nlohmann::json& j, KeyPublishToUserGroup const& dc);
}
