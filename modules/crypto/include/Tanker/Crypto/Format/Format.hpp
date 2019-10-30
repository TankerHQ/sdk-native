#pragma once

#include <Tanker/Crypto/IsCryptographicType.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <cppcodec/base64_url.hpp>
#include <fmt/format.h>

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace fmt
{
template <typename CryptoType>
struct formatter<
    CryptoType,
    char,
    std::enable_if_t<Tanker::Crypto::IsCryptographicType<CryptoType>::value>>
{
  using base = formatter<typename CryptoType::array_t>;

  bool useSafe = false;

  template <typename ParserContext>
  constexpr auto parse(ParserContext& ctx)
  {
    auto it = ctx.begin();
    if (*it == ':')
      ++it;
    auto end = it;
    while (end != ctx.end() && *end != '}')
      ++end;
    if (*it == 'S')
      useSafe = true;
    else if (*it == 's' || it == end)
      useSafe = false;
    else
      throw fmt::format_error("invalid format specifier");
    return end;
  }

  auto format_crypto_array(std::uint8_t const* beg, std::size_t size)
  {
    return useSafe ? cppcodec::base64_url::encode<std::string>(beg, size) :
                     cppcodec::base64_rfc4648::encode<std::string>(beg, size);
  }

  template <typename FormatContext>
  auto format(CryptoType const& c, FormatContext& ctx)
  {
    return format_to(
        ctx.out(), "{:s}", format_crypto_array(c.data(), c.size()));
  }
};
}
