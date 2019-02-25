#pragma once

#include <Tanker/Crypto/Traits.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Crypto/base64.hpp>

#include <fmt/format.h>

#include <type_traits>

namespace fmt
{
template <typename CryptoType>
struct formatter<
    CryptoType,
    char,
    std::enable_if_t<Tanker::Crypto::is_cryptographic_type<CryptoType>::value>>
{
  using base = formatter<typename CryptoType::array_t>;

  bool useSafe = false;

  constexpr auto parse(fmt::parse_context& ctx)
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

  auto format_crypto_array(uint8_t const* beg, std::size_t size)
  {
    return useSafe ? Tanker::safeBase64::encode<std::string>(beg, size) :
                     Tanker::base64::encode<std::string>(beg, size);
  }

  auto format(CryptoType const& c, format_context& ctx)
  {
    return format_to(
        ctx.out(), "{:s}", format_crypto_array(c.data(), c.size()));
  }
};
}
