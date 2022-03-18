#include <Helpers/Config.hpp>

#include <fmt/format.h>

#include <nlohmann/json.hpp>

#include <stdexcept>
#include <string_view>

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
  static auto const oidc =
      OidcConfig{getSafeEnv("TANKER_OIDC_CLIENT_SECRET"),
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

std::string const& appManagementToken()
{
  static auto const value = getSafeEnv("TANKER_MANAGEMENT_API_ACCESS_TOKEN");
  return value;
}

std::string const& appManagementUrl()
{
  static auto const value = getSafeEnv("TANKER_MANAGEMENT_API_URL");
  return value;
}

std::string const& appdUrl()
{
  static auto const value = getSafeEnv("TANKER_APPD_URL");
  return value;
}

std::string const& environmentName()
{
  static auto const value =
      getSafeEnv("TANKER_MANAGEMENT_API_DEFAULT_ENVIRONMENT_NAME");
  return value;
}

std::string const& trustchaindUrl()
{
  static auto const value = getSafeEnv("TANKER_TRUSTCHAIND_URL");
  return value;
}
}
}
