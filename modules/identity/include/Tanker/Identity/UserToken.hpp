#pragma once

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Types/UserId.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <cppcodec/base64_url.hpp>
#include <gsl-lite.hpp>
#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace Tanker
{
namespace Identity
{

struct UserToken
{
  Delegation delegation;
  Tanker::Crypto::SymmetricKey userSecret;
};

bool operator==(UserToken const&, UserToken const&) noexcept;
bool operator!=(UserToken const&, UserToken const&) noexcept;

void from_json(nlohmann::json const& j, UserToken& result);
void to_json(nlohmann::json& j, UserToken const& result);

std::string generateUserToken(std::string const& trustchainId,
                              std::string const& trustchainPrivateKey,
                              SUserId const& userId);
}
}
