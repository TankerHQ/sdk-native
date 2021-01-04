#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Trustchain/UserId.hpp>

namespace Tanker
{
namespace Identity
{
constexpr auto USER_SECRET_SIZE = 32u;

std::vector<uint8_t> userSecretHash(gsl::span<uint8_t const> secretRand,
                                    Trustchain::UserId const& userId);

Tanker::Crypto::SymmetricKey generateUserSecret(
    Trustchain::UserId const& userId);
}
}
