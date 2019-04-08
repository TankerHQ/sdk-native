//
// Copyright (c) 2017 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

#pragma once

#include <cstdlib>
#include <stdexcept>
#include <type_traits>
#include <vector>

#include <gsl-lite.hpp>

namespace Tanker
{
namespace Serialization
{
// https://developers.google.com/protocol-buffers/docs/encoding#varints

constexpr std::size_t varint_size(std::size_t value)
{
  std::size_t n = 1;
  while (value > 127)
  {
    ++n;
    value /= 128;
  }
  return n;
}

inline std::pair<std::size_t, gsl::span<uint8_t const>> varint_read(
    gsl::span<uint8_t const> data)
{
  std::size_t value = 0;
  std::size_t factor = 1;
  while ((data.at(0) & 0x80) != 0)
  {
    value += (data.at(0) & 0x7f) * factor;
    factor *= 128;
    data = data.subspan(1);
  }
  value += data.at(0) * factor;
  data = data.subspan(1);
  return {value, data};
}

inline std::uint8_t* varint_write(std::uint8_t* it, std::size_t value)
{
  while (value > 127)
  {
    *it++ = (0x80 | value);
    value /= 128;
  }
  *it++ = value;
  return it;
}
}
}
