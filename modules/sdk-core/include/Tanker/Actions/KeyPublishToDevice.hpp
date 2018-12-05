#pragma once

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Index.hpp>
#include <Tanker/Nature.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Types/DeviceId.hpp>

#include <gsl-lite.hpp>
#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace Tanker
{
struct KeyPublishToDevice
{
  DeviceId recipient;
  Crypto::Mac mac;
  Crypto::EncryptedSymmetricKey key;

  Nature nature() const;
  std::vector<Index> makeIndexes() const;
};

bool operator==(KeyPublishToDevice const& l, KeyPublishToDevice const& r);
bool operator!=(KeyPublishToDevice const& l, KeyPublishToDevice const& r);

KeyPublishToDevice deserializeKeyPublishToDevice(gsl::span<uint8_t const> data);

void to_json(nlohmann::json& j, KeyPublishToDevice const& kp);

template <typename OutputIterator>
void to_serialized(OutputIterator it, KeyPublishToDevice const& kp)
{
  Serialization::serialize(it, kp.recipient);
  Serialization::serialize(it, kp.mac);
  Serialization::varint_write(it, kp.key.size());
  Serialization::serialize(it, kp.key);
}

std::size_t serialized_size(KeyPublishToDevice const& kp);
}
