#include <Helpers/Config.hpp>

#include <fmt/format.h>

#include <nlohmann/json.hpp>

#include <stdexcept>

namespace Tanker
{
namespace TestConstants
{
namespace
{
std::string getSafeEnv(std::string_view key)
{
  auto env = std::getenv(key.data());
  if (env == nullptr)
    throw std::runtime_error(fmt::format("No {} set up", key));
  return env;
}
}

OidcConfig const& oidcConfig()
{
  static OidcConfig oidc = {
      getSafeEnv("TANKER_OIDC_CLIENT_SECRET"),
      getSafeEnv("TANKER_OIDC_CLIENT_ID"),
      getSafeEnv("TANKER_OIDC_PROVIDER"),
      {{"kevin",
        {getSafeEnv("TANKER_OIDC_KEVIN_EMAIL"),
         getSafeEnv("TANKER_OIDC_KEVIN_REFRESH_TOKEN")}},
       {"martine",
        {getSafeEnv("TANKER_OIDC_MARTINE_EMAIL"),
         getSafeEnv("TANKER_OIDC_MARTINE_REFRESH_TOKEN")}}}};
  return oidc;
}

std::string const& appdUrl()
{
  static auto value = getSafeEnv("TANKER_APPD_URL");
  return value;
}

std::string_view admindUrl()
{
  static auto value = getSafeEnv("TANKER_ADMIND_URL");
  return value;
}

std::string const& idToken()
{
  static auto value = getSafeEnv("TANKER_ID_TOKEN");
  return value;
}
}
}
