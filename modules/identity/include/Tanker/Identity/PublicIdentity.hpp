#pragma once

#include <Tanker/Identity/Utils.hpp>

#include <Tanker/Types/TrustchainId.hpp>
#include <Tanker/Types/UserId.hpp>

#include <mpark/variant.hpp>
#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Identity
{
struct Identity;

struct PublicNormalIdentity
{
  TrustchainId trustchainId;
  UserId userId;
};

using PublicIdentity = mpark::variant<PublicNormalIdentity>;

PublicIdentity getPublicIdentity(Identity const& identity);

std::string getPublicIdentity(std::string const& identity);

void from_json(nlohmann::json const& j, PublicIdentity& result);
void to_json(nlohmann::json& j, PublicIdentity const& identity);
std::string to_string(PublicIdentity const& identity);
template <>
PublicIdentity from_string(std::string const&);
}
}
