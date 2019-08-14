#pragma once

#include <tconcurrent/coroutine.hpp>

#include <gsl-lite.hpp>

#include <cstdint>

namespace Tanker
{
inline auto bufferToInputSource(gsl::span<std::uint8_t const> buffer)
{
  return
      [index = 0u, buffer](std::uint8_t* out,
                           std::int64_t n) mutable -> tc::cotask<std::int64_t> {
        auto const toRead =
            std::min(n, static_cast<std::int64_t>(buffer.size()) - index);
        std::copy_n(buffer.data() + index, toRead, out);
        index += toRead;
        TC_RETURN(toRead);
      };
}

inline tc::cotask<int64_t> readStream(gsl::span<uint8_t> out,
                                      StreamInputSource const& source)
{
  auto totalRead = 0lu;
  while (totalRead != out.size())
  {
    auto const nbRead =
        TC_AWAIT(source(out.data() + totalRead, out.size() - totalRead));
    if (nbRead == 0)
      break;
    totalRead += nbRead;
  }
  TC_RETURN(totalRead);
}
}
