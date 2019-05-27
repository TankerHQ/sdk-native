#pragma once

#include <Tanker/Errors/Exception.hpp>

#include <fmt/format.h>

#include <string>
#include <system_error>
#include <type_traits>

namespace Tanker
{
namespace Verif
{
template <typename... Args>
void ensures(bool condition,
             std::error_code code,
             std::string const& formatString,
             Args&&... formatArgs)
{
  if (!condition)
  {
    throw Errors::Exception(
        code, fmt::vformat(formatString, fmt::make_format_args(formatArgs...)));
  }
}
}
}
