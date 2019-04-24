#pragma once

#include <Tanker/Trustchain/Actions/KeyPublishToProvisionalUser.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void from_serialized(Serialization::SerializedSource&,
                     KeyPublishToProvisionalUser&);
std::uint8_t* to_serialized(std::uint8_t*, KeyPublishToProvisionalUser const&);

constexpr std::size_t serialized_size(KeyPublishToProvisionalUser const&)
{
  return (Crypto::PublicSignatureKey::arraySize * 2) + ResourceId::arraySize +
         Crypto::TwoTimesSealedSymmetricKey::arraySize;
}
}
}
}
