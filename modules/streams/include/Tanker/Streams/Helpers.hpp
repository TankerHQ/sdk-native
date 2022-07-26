#pragma once

#include <Tanker/Streams/InputSource.hpp>

#include <gsl/gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstdint>
#include <utility>
#include <vector>

namespace Tanker
{
namespace Streams
{
InputSource bufferViewToInputSource(gsl::span<uint8_t const> buffer);
InputSource bufferToInputSource(std::vector<uint8_t> buffer);

template <typename T>
tc::cotask<int64_t> readStream(gsl::span<uint8_t> out, T&& source)
{
  auto totalRead = 0lu;
  while (!out.empty())
  {
    auto const nbRead = TC_AWAIT(std::forward<T>(source)(out));
    if (nbRead == 0)
      break;
    out = out.subspan(nbRead);
    totalRead += nbRead;
  }
  TC_RETURN(totalRead);
}

template <typename T>
tc::cotask<std::vector<uint8_t>> readAllStream(T&& source)
{
  std::vector<uint8_t> out;
  auto const blockSize = 1024 * 1024;
  auto pos = 0;
  while (true)
  {
    auto availableRoom = out.size() - pos;
    if (availableRoom == 0)
    {
      out.resize(pos + blockSize);
      availableRoom = blockSize;
    }
    auto const nbRead =
        TC_AWAIT(std::forward<T>(source)(gsl::make_span(out).subspan(pos)));
    if (nbRead == 0)
    {
      out.resize(pos + nbRead);
      TC_RETURN(out);
    }
    pos += nbRead;
  }
}
}
}
