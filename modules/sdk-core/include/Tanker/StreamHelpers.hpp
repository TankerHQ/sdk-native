#pragma once

#include <tconcurrent/coroutine.hpp>

#include <gsl-lite.hpp>

#include <cstdint>

namespace Tanker
{
namespace detail
{
template <typename T>
inline auto bufferToInputSource(T&& buffer)
{
  return [index = 0u, buffer = std::forward<T>(buffer)](
             std::uint8_t* out,
             std::int64_t n) mutable -> tc::cotask<std::int64_t> {
    auto const toRead =
        std::min(n, static_cast<std::int64_t>(buffer.size()) - index);
    std::copy_n(buffer.data() + index, toRead, out);
    index += toRead;
    TC_RETURN(toRead);
  };
}
}

inline auto bufferViewToInputSource(gsl::span<uint8_t const> buffer)
{
  return detail::bufferToInputSource(buffer);
}

inline auto bufferToInputSource(std::vector<uint8_t> buffer)
{
  return detail::bufferToInputSource(std::move(buffer));
}

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
