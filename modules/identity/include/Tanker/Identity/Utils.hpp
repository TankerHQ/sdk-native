#pragma once
#include <Tanker/Identity/UserToken.hpp>

namespace Tanker
{
namespace Identity
{
struct UserToken;

constexpr auto USER_SECRET_SIZE = 32u;

std::vector<uint8_t> userSecretHash(gsl::span<uint8_t const> secretRand,
                                    UserId const& userId);

Tanker::Crypto::SymmetricKey generateUserSecret(UserId const& userId);

UserToken extract(std::string const& userToken);

UserToken generateUserToken(
    Tanker::Crypto::PrivateSignatureKey const& trustchainPrivateKey,
    UserId const& userId);

template <typename I>
I from_string(std::string const&);
}
}
