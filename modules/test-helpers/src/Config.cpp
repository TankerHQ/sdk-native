#include <Helpers/Config.hpp>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <fmt/core.h>
#include <fstream>
#include <iterator>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <utility>

namespace Tanker
{
using namespace std::literals::string_literals;
namespace
{

std::string getSafeEnv(std::string key)
{
  auto env = std::getenv(key.c_str());
  if (env == nullptr)
    throw std::runtime_error(fmt::format("No {} set up", key));
  return env;
}

struct Config
{
  std::string url;
  std::string idToken;
};

void from_json(const nlohmann::json& j, Config& c)
{
  j.at("url").get_to(c.url);
  j.at("idToken").get_to(c.idToken);
}

Config parseConfigFromFile(std::string configName)
{
  auto const configPath = getSafeEnv("TANKER_CONFIG_FILEPATH");
  std::ifstream file(configPath);
  if (!file.is_open())
    throw std::runtime_error(
        fmt::format("Could not open config file '{}'\n", configPath));
  nlohmann::json configs;
  file >> configs;
  auto const found = configs.find(configName);
  if (found == end(configs))
    throw std::runtime_error(fmt::format(
        "Bad TANKER_CONFIG_NAME, '{}' is not a valid value", configName));
  return found->get<Config>();
}

Config createConfig()
{
  auto const projectConfig = getSafeEnv("TANKER_CONFIG_NAME");
  return parseConfigFromFile(projectConfig);
}

Config const& getConfig()
{
  static auto const config = createConfig();
  return config;
}
}

namespace TestConstants
{

std::string const& trustchainUrl()
{
  return getConfig().url;
}

std::string const& idToken()
{
  return getConfig().idToken;
}
}
}
