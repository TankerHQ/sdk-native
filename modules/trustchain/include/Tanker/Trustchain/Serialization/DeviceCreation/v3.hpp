#pragma once

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
class DeviceCreation3;

void from_serialized(Serialization::SerializedSource&, DeviceCreation3&);

std::uint8_t* to_serialized(std::uint8_t*, DeviceCreation3 const&);

constexpr std::size_t serialized_size(DeviceCreation3 const&)
{
  return (Crypto::PublicSignatureKey::arraySize * 2) + UserId::arraySize +
         Crypto::Signature::arraySize +
         (Crypto::PublicEncryptionKey::arraySize * 2) +
         Crypto::SealedPrivateEncryptionKey::arraySize + sizeof(bool);
}
}
}
}
