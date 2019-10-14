#include <Tanker/Identity/SecretIdentity.hpp>

#include <Tanker/Identity/Extract.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Identity
{
void from_json(nlohmann::json const& j, SecretIdentity& identity)
{
  auto const target = j.at("target").get<std::string>();
  if (target == "user")
    identity = j.get<SecretPermanentIdentity>();
  else
    identity = j.get<SecretProvisionalIdentity>();
}

void to_json(nlohmann::json& j, SecretIdentity const& identity)
{
  boost::variant2::visit([&](auto const& i) { nlohmann::to_json(j, i); }, identity);
}

std::string to_string(SecretIdentity const& identity)
{
  return boost::variant2::visit([](auto const& i) { return to_string(i); }, identity);
}
}
}
