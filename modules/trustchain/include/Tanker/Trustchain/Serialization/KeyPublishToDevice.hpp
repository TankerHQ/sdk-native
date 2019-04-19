#pragma once

#include <Tanker/Trustchain/Actions/KeyPublishToDevice.hpp>
#include <Tanker/Serialization/Varint.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void from_serialized(Serialization::SerializedSource&, KeyPublishToDevice&);
std::uint8_t* to_serialized(std::uint8_t*, KeyPublishToDevice const&);

constexpr std::size_t serialized_size(KeyPublishToDevice const&)
{
  return DeviceId::arraySize + Crypto::Mac::arraySize +
         Serialization::varint_size(Crypto::EncryptedSymmetricKey::arraySize) +
         Crypto::EncryptedSymmetricKey::arraySize;
}
}
}
}
