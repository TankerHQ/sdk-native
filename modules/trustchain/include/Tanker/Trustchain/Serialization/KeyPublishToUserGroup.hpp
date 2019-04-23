#pragma once

#include <Tanker/Trustchain/Actions/KeyPublishToUserGroup.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void from_serialized(Serialization::SerializedSource&, KeyPublishToUserGroup&);
std::uint8_t* to_serialized(std::uint8_t*, KeyPublishToUserGroup const&);

constexpr std::size_t serialized_size(KeyPublishToUserGroup const&)
{
  return Crypto::PublicEncryptionKey::arraySize + Crypto::Mac::arraySize +
         Crypto::SealedSymmetricKey::arraySize;
}
}
}
}
