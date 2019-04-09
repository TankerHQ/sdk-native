#pragma once

#include <Tanker/Identity/PublicPermanentIdentity.hpp>

#include <mpark/variant.hpp>

namespace Tanker
{
namespace Identity
{
struct SecretPermanentIdentity;

using PublicIdentity = mpark::variant<PublicPermanentIdentity>;

PublicIdentity getPublicIdentity(SecretPermanentIdentity const& identity);

std::string getPublicIdentity(std::string const& identity);

void from_json(nlohmann::json const& j, PublicIdentity& identity);
void to_json(nlohmann::json& j, PublicIdentity const& identity);
std::string to_string(PublicIdentity const& identity);
}
}
