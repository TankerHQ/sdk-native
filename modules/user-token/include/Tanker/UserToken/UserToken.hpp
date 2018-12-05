#pragma once

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Types/UserId.hpp>
#include <Tanker/UserToken/Delegation.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <cppcodec/base64_url.hpp>
#include <gsl-lite.hpp>
#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace Tanker
{
namespace UserToken
{
using base64 = cppcodec::base64_rfc4648;
using safeBase64 = cppcodec::base64_url;

constexpr auto USER_SECRET_SIZE = 32;

struct UserToken
{
  Delegation delegation;
  Tanker::Crypto::SymmetricKey userSecret;
};

bool operator==(UserToken const&, UserToken const&) noexcept;
bool operator!=(UserToken const&, UserToken const&) noexcept;

void from_json(nlohmann::json const& j, UserToken& result);
void to_json(nlohmann::json& j, UserToken const& result);

UserToken extract(std::string const& userToken);

std::vector<uint8_t> userSecretHash(gsl::span<uint8_t const> secretRand,
                                    UserId const& userId);

Tanker::Crypto::SymmetricKey generateUserSecret(UserId const& userId);

std::string generateUserToken(std::string const& trustchainId,
                              std::string const& trustchainPrivateKey,
                              SUserId const& userId);

std::string generateUserToken(
    Tanker::Crypto::PrivateSignatureKey const& trustchainPrivateKey,
    UserId const& userId);
}
}
