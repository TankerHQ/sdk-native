#pragma once

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Format/Enum.hpp>

#include <range/v3/view/take.hpp>

#include <catch2/catch_tostring.hpp>

template <>
struct Catch::StringMaker<std::vector<unsigned char>>
{
  static std::string convert(std::vector<unsigned char> const& value)
  {
    if (value.size() > 32)
    {
      auto span = value | ranges::views::take(32);
      return fmt::format("{{ {}, <size:{}>... }}", fmt::join(span, ", "), value.size());
    }
    return Catch::Detail::rangeToString(std::begin(value), std::end(value));
  }
};
