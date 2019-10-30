#pragma once

#include <fmt/format.h>

#include <string>
#include <type_traits>
#include <utility>

namespace Tanker
{
namespace Format
{
namespace detail
{
template <typename T, typename = void>
struct HasToString : std::false_type
{
};

template <typename T>
struct HasToString<
    T,
    std::enable_if_t<std::is_same<decltype(to_string(std::declval<T>())),
                                  std::string>::value>> : std::true_type
{
};
}
}
}

namespace fmt
{
template <typename EnumType>
struct formatter<
    EnumType,
    char,
    std::enable_if_t<std::is_enum<EnumType>::value&& ::Tanker::Format::detail::
                         HasToString<EnumType>::value>>
{
  int flag = 0;

  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
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

  template <typename FormatContext>
  auto format(EnumType n, FormatContext& ctx) -> decltype(ctx.out())
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
