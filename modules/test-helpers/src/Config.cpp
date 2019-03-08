#include <Helpers/Config.hpp>
#include <Helpers/JsonFile.hpp>

#include <fmt/core.h>

#include <nlohmann/json.hpp>

#include <optional.hpp>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <sstream>
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

Config selectConfig(nlohmann::json const& configs,
                    std::string const& configName)
{
  auto const found = configs.find(configName);
  if (found == end(configs))
    throw std::runtime_error(fmt::format(
        "Bad TANKER_CONFIG_NAME, '{}' is not a valid value", configName));
  return found->get<Config>();
}

Config loadConfig()
{
  auto const projectConfig = getSafeEnv("TANKER_CONFIG_NAME");
  auto const configPath = getSafeEnv("TANKER_CONFIG_FILEPATH");
  return selectConfig(loadJson(configPath), projectConfig);
}

nonstd::optional<Config> config;

Config const& getConfig()
{
  if (!config)
    config = loadConfig();
  return *config;
}
}

namespace TestConstants
{
void setConfig(std::string const& cfg, std::string const& env)
{
  config = selectConfig(nlohmann::json::parse(cfg), env);
}

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
