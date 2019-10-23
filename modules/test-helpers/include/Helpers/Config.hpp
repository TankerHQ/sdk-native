#pragma once

#include <nlohmann/json_fwd.hpp>

#include <string>

namespace Tanker
{
namespace TestConstants
{
struct ServerConfig
{
  std::string url;
  std::string idToken;
};

struct User
{
  std::string email;
  std::string refreshToken;
};

struct OidcConfig
{
  std::string clientSecret;
  std::string clientId;
  std::string provider;
  std::map<std::string, User> users;
};

void setConfig(std::string const& cfg, std::string const& env);
std::string const& trustchainUrl();
std::string const& idToken();
ServerConfig const& serverConfig();
OidcConfig const& oidcConfig();
}
}
