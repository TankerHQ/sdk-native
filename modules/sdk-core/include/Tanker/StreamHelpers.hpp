#pragma once

#include <Tanker/StreamInputSource.hpp>

#include <tconcurrent/coroutine.hpp>

#include <gsl-lite.hpp>

#include <cstdint>

namespace Tanker
{
StreamInputSource bufferViewToInputSource(gsl::span<uint8_t const> buffer);
StreamInputSource bufferToInputSource(std::vector<uint8_t> buffer);

template <typename T>
tc::cotask<int64_t> readStream(gsl::span<uint8_t> out, T&& source)
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
    auto const nbRead = TC_AWAIT(source(&out[pos], availableRoom));
    if (nbRead == 0)
    {
      out.resize(pos + nbRead);
      TC_RETURN(out);
    }
    pos += nbRead;
  }
}
}
