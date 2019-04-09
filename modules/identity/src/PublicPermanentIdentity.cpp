#include <Tanker/Identity/PublicPermanentIdentity.hpp>

#include <nlohmann/json.hpp>

#include <cppcodec/base64_rfc4648.hpp>

namespace Tanker
{
namespace Identity
{
void from_json(nlohmann::json const& j, PublicPermanentIdentity& identity)
{
  identity = PublicPermanentIdentity{j.at("trustchain_id").get<TrustchainId>(),
                                     j.at("value").get<UserId>()};
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
