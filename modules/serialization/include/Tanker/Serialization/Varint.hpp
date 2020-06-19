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

#include <gsl/gsl-lite.hpp>

namespace Tanker
{
namespace Serialization
{
// https://developers.google.com/protocol-buffers/docs/encoding#varints

constexpr std::size_t varint_size(std::uint32_t value)
{
  std::size_t n = 1;
  while (value > 127)
  {
    ++n;
    value /= 128;
  }
  return n;
}

std::pair<std::uint32_t, gsl::span<uint8_t const>> varint_read(
    gsl::span<uint8_t const> data);

std::uint8_t* varint_write(std::uint8_t* it, std::uint32_t value);
}
}
