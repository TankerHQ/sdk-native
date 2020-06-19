#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>

#include <gsl/gsl-lite.hpp>

#include <cstdint>

namespace Tanker::Trustchain
{
Crypto::Hash computeHash(Actions::Nature,
                         Crypto::Hash const& author,
                         gsl::span<std::uint8_t const> serializedPayload);
}
