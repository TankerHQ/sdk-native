#include <Tanker/Identity/PublicIdentity.hpp>

#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/Identity.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Identity
{
PublicIdentity getPublicIdentity(Identity const& identity)
{
  return PublicIdentity(
      PublicNormalIdentity{identity.trustchainId, identity.delegation.userId});
}

std::string getPublicIdentity(std::string const& token)
{
  auto const j = extract(token);
  if (j.find("user_id") != j.end())
    return to_string(getPublicIdentity(j.get<Identity>()));
  else
    throw std::runtime_error("getPublicIdentity not implemented");
}

void from_json(nlohmann::json const& j, PublicIdentity& identity)
{
  auto const target = j.at("target").get<std::string>();
  if (target == "user")
    identity = PublicNormalIdentity{j.at("trustchain_id").get<TrustchainId>(),
                                    j.at("user_id").get<UserId>()};
  else
    throw std::runtime_error(
        "PublicIdentity deserialization type not implemented");
}

void to_json(nlohmann::json& j, PublicIdentity const& publicIdentity)
{
  if (auto const identity =
          mpark::get_if<PublicNormalIdentity>(&publicIdentity))
  {
    j["user_id"] = identity->userId;
    j["trustchain_id"] = identity->trustchainId;
    j["target"] = "user";
  }
  else
    throw std::runtime_error(
        "PublicIdentity serialiation type not implemented");
}

std::string to_string(PublicIdentity const& identity)
{
  return base64::encode(nlohmann::json(identity).dump());
}
}
}
