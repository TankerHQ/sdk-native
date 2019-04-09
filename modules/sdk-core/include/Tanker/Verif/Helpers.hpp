#pragma once

#include <Tanker/Error.hpp>

#include <fmt/format.h>

#include <string>
#include <type_traits>

namespace Tanker
{
namespace Verif
{
template <typename... Args>
void ensures(bool condition,
             Error::VerificationCode code,
             std::string const& formatString,
             Args&&... formatArgs)
{
  if (!condition)
  {
    throw Error::VerificationFailed(
        code, fmt::vformat(formatString, fmt::make_format_args(formatArgs...)));
  }
}
}
}
