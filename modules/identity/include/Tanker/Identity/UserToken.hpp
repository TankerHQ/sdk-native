#pragma once

#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Types/SUserId.hpp>

#include <nlohmann/json_fwd.hpp>

#include <string>

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
