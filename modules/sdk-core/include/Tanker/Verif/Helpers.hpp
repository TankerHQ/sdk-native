#pragma once

#include <Tanker/Entry.hpp>
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
             fmt::string_view formatString,
             Args&&... formatArgs)
{
  if (!condition)
  {
    throw Errors::Exception(
        code,
        fmt::vformat(formatString, {fmt::make_format_args(formatArgs...)}));
  }
}

// This method should never be used outside the verification code
inline Entry makeVerifiedEntry(Trustchain::ServerEntry const& se)
{
  return {se.action().nature(), se.author(), se.action(), se.hash()};
}
}
}
