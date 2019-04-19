#pragma once

#include <Tanker/Trustchain/Actions/TrustchainCreation.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void from_serialized(Serialization::SerializedSource&, TrustchainCreation&);
std::uint8_t* to_serialized(std::uint8_t*, TrustchainCreation const&);

constexpr std::size_t serialized_size(TrustchainCreation const&)
{
  return Crypto::PublicSignatureKey::arraySize;
}
}
}
}

