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
struct SecretPermanentIdentity;

struct PublicPermanentIdentity
{
  TrustchainId trustchainId;
  UserId userId;
};

using PublicIdentity = mpark::variant<PublicPermanentIdentity>;

PublicIdentity getPublicIdentity(SecretPermanentIdentity const& identity);

std::string getPublicIdentity(std::string const& identity);

void from_json(nlohmann::json const& j, PublicIdentity& result);
void to_json(nlohmann::json& j, PublicIdentity const& identity);
std::string to_string(PublicIdentity const& identity);
}
}
