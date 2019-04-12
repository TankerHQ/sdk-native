#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/Unlock/Methods.hpp>

#include <flags/flags.hpp>
#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Unlock
{
void to_json(nlohmann::json& j, Methods methods)
{
  if (methods & Method::Password)
    j.push_back({{"type", "password"}});
  else if (methods & Method::Email)
    j.push_back({{"type", "email"}});
  else
    assert(0 && "update this");
}

void from_json(nlohmann::json const& j, Methods& m)
{
  m = Methods{};
  for (auto const method : j)
  {
    auto const value = method.at("type").get<std::string>();
    if (value == "password")
      m |= Method::Password;
    else if (value == "email")
      m |= Method::Email;
    else
      assert(0 && "update this");
  }
}
}
}
