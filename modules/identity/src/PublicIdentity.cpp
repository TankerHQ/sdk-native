#include <Tanker/Identity/PublicIdentity.hpp>

#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/PublicPermanentIdentity.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Identity
{
PublicIdentity getPublicIdentity(SecretPermanentIdentity const& identity)
{
  return PublicIdentity(PublicPermanentIdentity{identity.trustchainId,
                                                identity.delegation.userId});
}

std::string getPublicIdentity(std::string const& token)
{
  return to_string(
      getPublicIdentity(extract(token).get<SecretPermanentIdentity>()));
}

void from_json(nlohmann::json const& j, PublicIdentity& identity)
{
  auto const target = j.at("target").get<std::string>();
  if (target == "user")
    identity = j.get<PublicPermanentIdentity>();
  else
    throw std::runtime_error(
        "PublicIdentity deserialization type not implemented: " + target);
}

void to_json(nlohmann::json& j, PublicIdentity const& identity)
{
  mpark::visit([&](auto const& i) { nlohmann::to_json(j, i); }, identity);
}

std::string to_string(PublicIdentity const& identity)
{
  return mpark::visit([](auto const& i) { return to_string(i); }, identity);
}
}
}
