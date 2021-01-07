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

std::string const& trustchaindUrl()
{
  static auto const value = getSafeEnv("TANKER_TRUSTCHAIND_URL");
  return value;
}

std::string const& appdUrl()
{
  static auto const value = getSafeEnv("TANKER_APPD_URL");
  return value;
}

std::string_view admindUrl()
{
  static auto const value = getSafeEnv("TANKER_ADMIND_URL");
  return value;
}

std::string const& idToken()
{
  static auto const value = getSafeEnv("TANKER_ID_TOKEN");
  return value;
}

AppConfig const& benchmarkApp()
{
  static auto const app = AppConfig{
      getSafeEnv("TANKER_BENCHMARK_APP_ID"),
      getSafeEnv("TANKER_BENCHMARK_APP_SECRET"),
  };
  return app;
}
}
}
