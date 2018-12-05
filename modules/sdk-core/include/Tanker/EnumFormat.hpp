#pragma once

#include <fmt/format.h>

#include <Tanker/EnumTrait.hpp>

#include <type_traits>

namespace Tanker
{
struct EnumParser
{
  int flag = 0;

  constexpr auto parse(fmt::parse_context& ctx)
  {
    auto it = ctx.begin();
    if (*it == ':')
      ++it;
    auto end = it;
    while (end != ctx.end() && *end != '}')
      ++end;
    if (it + 1 < end)
      throw fmt::format_error("invalid specifier");

    if (*it == 'd')
      flag |= 0x1;
    else if (*it == 's')
      flag |= 0x2;
    else if (*it == 'e' || it == end)
      flag |= 0x3;
    else
      throw fmt::format_error("invalid specifier");
    return end;
  }

  template <typename EnumType>
  auto format(EnumType n, fmt::format_context& ctx) -> decltype(ctx.out())
  {
    auto out = ctx.out();
    if (this->flag == 0x3)
      out = fmt::format_to(out, "{:d} {:s}", static_cast<int>(n), to_string(n));
    else if (this->flag & 0x1)
      out = fmt::format_to(out, "{:d}", static_cast<int>(n));
    else if (this->flag & 0x2)
      out = fmt::format_to(out, "{:s}", to_string(n));
    return out;
  }
};
}

namespace fmt
{
template <typename EnumType>
struct formatter<EnumType,
                 char,
                 std::enable_if_t<Tanker::is_enum_type<EnumType>::value>>
  : Tanker::EnumParser
{
};
}
