#pragma once

namespace Tanker
{
struct OidcAuthorizationCode
{
  std::string provider_id;
  std::string authorization_code;
  std::string state;
};

inline bool operator==(OidcAuthorizationCode const& lhs, OidcAuthorizationCode const& rhs) noexcept
{
  return lhs.provider_id == rhs.provider_id && lhs.authorization_code == rhs.authorization_code && lhs.state == rhs.state;
}

inline bool operator!=(OidcAuthorizationCode const& lhs, OidcAuthorizationCode const& rhs) noexcept
{
  return !(lhs == rhs);
}

inline bool operator<(OidcAuthorizationCode const& lhs, OidcAuthorizationCode const& rhs) noexcept
{
  if (lhs.provider_id != rhs.provider_id)
    return lhs.provider_id < rhs.provider_id;
  else if (lhs.authorization_code != rhs.authorization_code)
    return lhs.authorization_code < rhs.authorization_code;
  else
    return lhs.state < rhs.state;
}
}
