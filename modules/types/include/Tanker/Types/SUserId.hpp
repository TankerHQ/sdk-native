#pragma once

#include <Tanker/Types/StringWrapper.hpp>

namespace Tanker
{
using SUserId = StringWrapper<struct UserIdTag>;

namespace type_literals
{
inline SUserId operator""_uid(const char* s, std::size_t t)
{
  return SUserId(s, t);
}
}
}
