#pragma once

#include <Tanker/Trustchain/Actions/KeyPublishToUser.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void from_serialized(Serialization::SerializedSource&, KeyPublishToUser&);
std::uint8_t* to_serialized(std::uint8_t*, KeyPublishToUser const&);

constexpr std::size_t serialized_size(KeyPublishToUser const&)
{
  return Crypto::PublicEncryptionKey::arraySize + ResourceId::arraySize +
         Crypto::SealedSymmetricKey::arraySize;
}
}
}
}
