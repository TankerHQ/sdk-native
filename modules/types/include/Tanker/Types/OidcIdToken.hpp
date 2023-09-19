#pragma once

#include <Tanker/Types/StringWrapper.hpp>

namespace Tanker
{
struct OidcIdToken
{
  std::string token;
  std::string provider_id;
  std::string provider_display_name;
};

inline bool operator==(OidcIdToken const& lhs,
                OidcIdToken const& rhs) noexcept
{
  return lhs.token == rhs.token
      && lhs.provider_id == rhs.provider_id
      && lhs.provider_display_name == rhs.provider_display_name;
}

inline bool operator!=(OidcIdToken const& lhs,
                OidcIdToken const& rhs) noexcept
{
  return !(lhs == rhs);
}

inline bool operator<(OidcIdToken const& lhs,
               OidcIdToken const& rhs) noexcept
{
  if (lhs.token < rhs.token)
    return true;
  else if (lhs.token > rhs.token)
    return false;
  else if (lhs.provider_id < rhs.provider_id)
    return true;
  else if (lhs.provider_id > rhs.provider_id)
    return false;
  else
    return lhs.provider_display_name < rhs.provider_display_name;
}
}
