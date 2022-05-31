#include <Tanker/ResourceKeys/KeysResult.hpp>

#include <tuple>

namespace Tanker::ResourceKeys
{
bool operator==(KeyResult const& lhs, KeyResult const& rhs)
{
  return std::tie(lhs.key, lhs.id) == std::tie(rhs.key, rhs.id);
}

bool operator!=(KeyResult const& lhs, KeyResult const& rhs)
{
  return !(lhs == rhs);
}
}
