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

std::string const& appdUrl();
std::string_view admindUrl();
std::string const& idToken();
OidcConfig const& oidcConfig();
}
}
