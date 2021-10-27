#include <Tanker/ResourceKeys/KeysResult.hpp>

#include <tuple>

namespace Tanker::ResourceKeys
{
bool operator==(KeyResult const& lhs, KeyResult const& rhs)
{
  return std::tie(lhs.key, lhs.resourceId) == std::tie(rhs.key, rhs.resourceId);
}

bool operator!=(KeyResult const& lhs, KeyResult const& rhs)
{
  return !(lhs == rhs);
}
}
