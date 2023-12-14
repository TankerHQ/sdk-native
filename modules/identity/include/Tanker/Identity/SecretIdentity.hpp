#pragma once

#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>

#include <boost/variant2/variant.hpp>

namespace Tanker
{
namespace Identity
{
using SecretIdentity = boost::variant2::variant<SecretPermanentIdentity, SecretProvisionalIdentity>;

void from_json(nlohmann::json const& j, SecretIdentity& identity);
void to_json(nlohmann::json& j, SecretIdentity const& identity);
std::string to_string(SecretIdentity const& identity);
}
}
