#pragma once

#include <map>
#include <string>
#include <string_view>

namespace Tanker
{
namespace TestConstants
{
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

struct AppConfig
{
  std::string appId;
  std::string appSecret;
};

std::string const& appManagementToken();
std::string const& appManagementUrl();
std::string const& appdUrl();
std::string const& environmentName();
std::string const& trustchaindUrl();
OidcConfig const& oidcConfig();
}
}
