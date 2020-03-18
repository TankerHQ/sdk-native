#include <Helpers/Config.hpp>
#include <Helpers/JsonFile.hpp>

#include <fmt/core.h>

#include <nlohmann/json.hpp>

#include <optional>

#include <cstdlib>
#include <stdexcept>

namespace Tanker
{
using namespace std::literals::string_literals;
namespace TestConstants
{

static void from_json(nlohmann::json const& j, ServerConfig& c)
{
  j.at("url").get_to(c.url);
  j.at("idToken").get_to(c.idToken);
}

static void from_json(nlohmann::json const& j, User& u)
{
  j.at("email").get_to(u.email);
  j.at("refreshToken").get_to(u.refreshToken);
}

static void from_json(nlohmann::json const& j, OidcConfig& c)
{
  j.at("clientSecret").get_to(c.clientSecret);
  j.at("clientId").get_to(c.clientId);
  j.at("provider").get_to(c.provider);
  j.at("users").get_to(c.users);
}

namespace
{
std::string getSafeEnv(std::string key)
{
  auto env = std::getenv(key.c_str());
  if (env == nullptr)
    throw std::runtime_error(fmt::format("No {} set up", key));
  return env;
}

struct TestConfig
{
  ServerConfig serverConfig;
  OidcConfig oidcConfig;
};
std::optional<TestConfig> testConfig;

auto selectConfig(nlohmann::json const& configs,
                  std::string const& serverConfig,
                  std::string const& oidcConfig = "googleAuth")
{
  auto const foundServer = configs.find(serverConfig);
  if (foundServer == end(configs))
    throw std::runtime_error(fmt::format(
        "Bad TANKER_CONFIG_NAME, '{}' is not a valid value", serverConfig));
  auto const& oidcs = configs.at("oidc");
  auto const foundOidc = oidcs.find("googleAuth");
  if (foundOidc == end(oidcs))
    throw std::runtime_error(
        fmt::format("Bad Oidc config, '{}' is not a valid value", oidcConfig));
  return TestConfig{foundServer->get<ServerConfig>(),
                    foundOidc->get<OidcConfig>()};
}

auto loadConfig()
{
  auto const projectConfig = getSafeEnv("TANKER_CONFIG_NAME");
  auto const configPath = getSafeEnv("TANKER_CONFIG_FILEPATH");
  return selectConfig(loadJson(configPath), projectConfig);
}

TestConfig const& getConfig()
{
  if (!testConfig)
    testConfig = loadConfig();
  return *testConfig;
}
}

void setConfig(std::string const& cfg, std::string const& env)
{
  testConfig = selectConfig(nlohmann::json::parse(cfg), env);
}

ServerConfig const& serverConfig()
{
  return getConfig().serverConfig;
}

OidcConfig const& oidcConfig()
{
  return getConfig().oidcConfig;
}

std::string const& trustchainUrl()
{
  return serverConfig().url;
}

std::string const& idToken()
{
  return serverConfig().idToken;
}
}
}
