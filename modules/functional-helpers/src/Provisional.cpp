#include <Tanker/Functional/Provisional.hpp>

#include <Tanker/Types/Overloaded.hpp>

#include <nlohmann/json.hpp>

namespace Tanker::Functional
{
void to_json(nlohmann::json& j, AppProvisionalUser const& user)
{
  boost::variant2::visit(overloaded{
                             [&](Email const& e) {
                               j["target"] = "email";
                               j["value"] = e;
                             },
                             [&](PhoneNumber const& e) {
                               j["target"] = "phone_number";
                               j["value"] = e;
                             },
                         },
                         user.value);
  j["identity"] = user.secretIdentity;
  j["publicIdentity"] = user.publicIdentity;
}

void from_json(nlohmann::json const& j, AppProvisionalUser& user)
{
  auto const target = j.at("target").get<std::string>();
  if (target == "email")
    user.value = j.at("value").get<Email>();
  else if (target == "phone_number")
    user.value = j.at("value").get<PhoneNumber>();
  else
    throw std::runtime_error("unknown AppProvisionalUser target " + target);
  user.secretIdentity = j.at("identity").get<SSecretProvisionalIdentity>();
  user.publicIdentity = j.at("publicIdentity").get<SPublicIdentity>();
}
}
