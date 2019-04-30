#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>

#include <gsl-lite.hpp>

#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace detail
{
Crypto::Hash computeHash(Actions::Nature,
                         Crypto::Hash const& parentHash,
                         gsl::span<std::uint8_t const> serializedPayload);
}
}
}
