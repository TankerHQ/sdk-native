#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class DeviceCreation2;

void from_serialized(Serialization::SerializedSource&, DeviceCreation2&);

std::uint8_t* to_serialized(std::uint8_t*, DeviceCreation2 const&);

constexpr std::size_t serialized_size(DeviceCreation2 const&)
{
  return (Crypto::PublicSignatureKey::arraySize * 2) + UserId::arraySize +
         Crypto::Signature::arraySize + Crypto::PublicEncryptionKey::arraySize +
         Crypto::Hash::arraySize;
}
}
}
}
