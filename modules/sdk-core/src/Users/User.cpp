#include <Tanker/Users/User.hpp>

#include <tuple>

namespace Tanker::Users
{
bool operator==(User const& l, User const& r)
{
  return std::tie(l.id, l.userKey, l.devices) ==
         std::tie(r.id, r.userKey, r.devices);
}
bool operator!=(User const& l, User const& r)
{
  return !(l == r);
}
}
