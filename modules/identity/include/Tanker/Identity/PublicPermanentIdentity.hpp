#pragma once

#include <Tanker/Identity/Utils.hpp>

#include <Tanker/Types/TrustchainId.hpp>
#include <Tanker/Types/UserId.hpp>

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Identity
{
struct PublicPermanentIdentity
{
  TrustchainId trustchainId;
  UserId userId;
};

void from_json(nlohmann::json const& j, PublicPermanentIdentity& result);
void to_json(nlohmann::json& j, PublicPermanentIdentity const& identity);
std::string to_string(PublicPermanentIdentity const& identity);
}
}
