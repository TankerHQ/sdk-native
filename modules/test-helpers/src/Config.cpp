#include <Helpers/Config.hpp>

#include <fmt/format.h>

#include <nlohmann/json.hpp>

#include <chrono>
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

std::chrono::minutes maxExecutionTimeout()
{
  using namespace std::string_view_literals;
  static auto const key = "TANKER_MAX_TEST_EXECUTION_TIMEOUT"sv;
  static auto const value = [] {
    auto v = getSafeEnv(key);
    try
    {
      return std::chrono::minutes{std::stoi(v)};
    }
    catch (std::exception& e)
    {
      throw std::runtime_error(fmt::format("Bad value for {}", key));
    }
  }();

  return value;
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

std::string const& verificationApiToken()
{
  static auto const value = getSafeEnv("TANKER_VERIFICATION_API_TEST_TOKEN");
  return value;
}
}
}
