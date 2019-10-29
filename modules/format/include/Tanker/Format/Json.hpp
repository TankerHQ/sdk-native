#pragma once

#include <Tanker/Format/Width.hpp>

#include <fmt/format.h>
#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Format
{
namespace detail
{
fmt::format_context::iterator formatJson(nlohmann::json const& j,
                                         int width,
                                         fmt::format_context::iterator ctx);
}
}
}

namespace fmt
{
template <>
struct formatter<nlohmann::json, char, void>
{
  int width = -1;

  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
  {
    auto it = ctx.begin();
    if (*it == ':')
      ++it;
    auto end = it;
    while (end != ctx.end() && *end != '}')
      ++end;
    while (it != end)
    {
      if (*it == 'j')
      {
        ++it;
        break;
      }
      else if (width == -1 && *it >= '1' && *it <= '9')
      {
        auto const res = Tanker::Format::parseWidth(it);
        width = res.first;
        if (width == 0)
          throw fmt::format_error("bad width format for json");
        it += res.second;
      }
      else
        throw fmt::format_error("invalid format specifier");
    }
    return end;
  }

  template <typename FormatContext>
  auto format(nlohmann::json const& j, FormatContext& ctx)
  {
    return Tanker::Format::detail::formatJson(j, this->width, ctx.out());
  }
};
}
