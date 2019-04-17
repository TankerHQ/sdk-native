#pragma once

#include <Tanker/Identity/PublicPermanentIdentity.hpp>
#include <Tanker/Identity/PublicProvisionalIdentity.hpp>

#include <mpark/variant.hpp>

namespace Tanker
{
namespace Identity
{
struct SecretPermanentIdentity;

using PublicIdentity =
    mpark::variant<PublicPermanentIdentity, PublicProvisionalIdentity>;

PublicIdentity getPublicIdentity(SecretPermanentIdentity const& identity);

std::string getPublicIdentity(std::string const& identity);

void from_json(nlohmann::json const& j, PublicIdentity& identity);
void to_json(nlohmann::json& j, PublicIdentity const& identity);
std::string to_string(PublicIdentity const& identity);
}
}
