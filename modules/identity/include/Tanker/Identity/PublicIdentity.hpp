#pragma once

#include <Tanker/Identity/PublicPermanentIdentity.hpp>
#include <Tanker/Identity/PublicProvisionalIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>

#include <boost/variant2/variant.hpp>

namespace Tanker
{
namespace Identity
{
struct SecretPermanentIdentity;

using PublicIdentity = boost::variant2::variant<PublicPermanentIdentity,
                                                PublicProvisionalIdentity>;

PublicIdentity getPublicIdentity(SecretPermanentIdentity const& identity);
PublicIdentity getPublicIdentity(SecretProvisionalIdentity const& identity);

std::string getPublicIdentity(std::string const& identity);

void from_json(nlohmann::json const& j, PublicIdentity& identity);
void to_json(nlohmann::json& j, PublicIdentity const& identity);
std::string to_string(PublicIdentity const& identity);
}
}
