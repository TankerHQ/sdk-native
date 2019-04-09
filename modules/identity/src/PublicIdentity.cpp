#include <Tanker/Identity/PublicIdentity.hpp>

#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>

#include <cppcodec/base64_rfc4648.hpp>
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
    identity = PublicPermanentIdentity{
        j.at("trustchain_id").get<TrustchainId>(), j.at("value").get<UserId>()};
  else
    throw std::runtime_error(
        "PublicIdentity deserialization type not implemented");
}

void to_json(nlohmann::json& j, PublicIdentity const& publicIdentity)
{
  if (auto const identity =
          mpark::get_if<PublicPermanentIdentity>(&publicIdentity))
  {
    j["value"] = identity->userId;
    j["trustchain_id"] = identity->trustchainId;
    j["target"] = "user";
  }
  else
    throw std::runtime_error(
        "PublicIdentity serialiation type not implemented");
}

std::string to_string(PublicIdentity const& identity)
{
  return cppcodec::base64_rfc4648::encode(nlohmann::json(identity).dump());
}
}
}
