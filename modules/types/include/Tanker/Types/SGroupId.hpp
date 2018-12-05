#pragma once

#include <Tanker/Types/StringWrapper.hpp>

namespace Tanker
{
using SGroupId = StringWrapper<struct GroupIdTag>;

namespace type_literals
{
inline SGroupId operator""_gid(const char* s, std::size_t t)
{
  return SGroupId(s, t);
}
}
}
