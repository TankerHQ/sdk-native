#pragma once

#include <fmt/core.h>
#include <fmt/format.h>
#include <nlohmann/json_fwd.hpp>

// Huge Hack to bypass nlohmann implicit conversions as always

namespace nlohmann
{
template <typename C>
fmt::internal::init<C, nlohmann::json const&, fmt::internal::custom_type>
make_value(nlohmann::json const& j)
{
  return {j};
}
}

namespace Tanker
{
namespace Crypto
{
namespace detail
{
inline constexpr int parse_width(const char* beg, char const** end)
{
  int width = 0;
  do
  {
    width = width * 10 + static_cast<int>(*beg - '0');
    ++beg;
  } while (*beg >= '0' && *beg <= '9');
  *end = beg;
  return width;
}

fmt::format_context::iterator format_json(nlohmann::json const& j,
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

  constexpr auto parse(fmt::parse_context& ctx)
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
        char const* nend = nullptr;
        width = Tanker::Crypto::detail::parse_width(it, &nend);
        if (width == 0 && nend == it)
          throw fmt::format_error("bad width format for json");
        it = nend;
      }
      else
        throw fmt::format_error("invalid format specifier");
    }
    return end;
  }

  auto format(nlohmann::json const& j, format_context& ctx)
  {
    return Tanker::Crypto::detail::format_json(j, this->width, ctx.out());
  }
};
}
