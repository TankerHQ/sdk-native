#pragma once

namespace Tanker
{
struct PreverifiedOidc
{
  std::string provider_id;
  std::string subject;
};

inline bool operator==(PreverifiedOidc const& lhs, PreverifiedOidc const& rhs) noexcept
{
  return lhs.provider_id == rhs.provider_id && lhs.subject == rhs.subject;
}

inline bool operator!=(PreverifiedOidc const& lhs, PreverifiedOidc const& rhs) noexcept
{
  return !(lhs == rhs);
}

inline bool operator<(PreverifiedOidc const& lhs, PreverifiedOidc const& rhs) noexcept
{
  if (lhs.provider_id < rhs.provider_id)
    return true;
  else if (lhs.provider_id > rhs.provider_id)
    return false;
  else
    return lhs.subject < rhs.subject;
}
}
