#include <Tanker/Identity/PublicPermanentIdentity.hpp>

#include <nlohmann/json.hpp>

#include <cppcodec/base64_rfc4648.hpp>

namespace Tanker
{
namespace Identity
{
void from_json(nlohmann::json const& j, PublicPermanentIdentity& identity)
{
  auto const target = j.at("target").get<std::string>();
  if (target != "user")
    throw std::runtime_error("unsupported public permanent identity target: " +
                             target);

  if (j.find("user_secret") != j.end())
  {
    throw std::invalid_argument(
        "Cannot deserialize SecretPermanentIdentity in "
        "PublicPermanentIdentity");
  }

  j.at("trustchain_id").get_to(identity.trustchainId);
  j.at("value").get_to(identity.userId);
}

void to_json(nlohmann::json& j, PublicPermanentIdentity const& identity)
{
  j["value"] = identity.userId;
  j["trustchain_id"] = identity.trustchainId;
  j["target"] = "user";
}

std::string to_string(PublicPermanentIdentity const& identity)
{
  return cppcodec::base64_rfc4648::encode(nlohmann::json(identity).dump());
}
}
}
