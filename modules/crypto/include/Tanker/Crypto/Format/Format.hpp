#pragma once

#include <Tanker/Crypto/IsCryptographicType.hpp>

#include <fmt/format.h>

#include <type_traits>

namespace Tanker::Crypto::Format
{
std::string format_crypto_array(bool useSafe,
                                bool padded,
                                std::uint8_t const* beg,
                                std::size_t size);
}

namespace fmt
{
template <typename CryptoType>
struct formatter<
    CryptoType,
    char,
    std::enable_if_t<Tanker::Crypto::IsCryptographicType<CryptoType>::value>>
{
  bool useSafe = false;
  bool padded = true;

  template <typename ParserContext>
  constexpr auto parse(ParserContext& ctx)
  {
    auto it = ctx.begin();
    if (it != ctx.end() && *it == ':')
      ++it;
    auto end = it;
    while (end != ctx.end() && *end != '}')
      ++end;
    for (; it != end; ++it)
    {
      if (*it == '#')
        padded = false;
      else if (*it == 'S')
        useSafe = true;
      else if (padded && *it == 's')
        useSafe = false;
      else
        throw fmt::format_error("invalid format specifier");
    }
    return end;
  }

  template <typename FormatContext>
  auto format(CryptoType const& c, FormatContext& ctx)
  {
    return format_to(ctx.out(),
                     "{:s}",
                     Tanker::Crypto::Format::format_crypto_array(
                         useSafe, padded, c.data(), c.size()));
  }
};
}
