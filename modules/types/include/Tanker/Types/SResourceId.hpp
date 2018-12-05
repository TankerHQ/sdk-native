#pragma once

#include <Tanker/Types/StringWrapper.hpp>

namespace Tanker
{
using SResourceId = StringWrapper<struct ResourceIdTag>;

namespace type_literals
{
inline SResourceId operator""_rid(const char* s, std::size_t t)
{
  return SResourceId(s, t);
}
}
}
