#pragma once

#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void from_serialized(Serialization::SerializedSource&,
                     ProvisionalIdentityClaim&);
std::uint8_t* to_serialized(std::uint8_t*, ProvisionalIdentityClaim const&);

constexpr std::size_t serialized_size(ProvisionalIdentityClaim const&)
{
  return UserId::arraySize + (Crypto::PublicSignatureKey::arraySize * 2) +
         (Crypto::Signature::arraySize * 2) +
         Crypto::PublicEncryptionKey::arraySize +
         ProvisionalIdentityClaim::SealedPrivateEncryptionKeys::arraySize;
}
}
}
}
