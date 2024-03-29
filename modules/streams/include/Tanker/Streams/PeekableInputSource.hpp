#pragma once

#include <Tanker/Streams/InputSource.hpp>

#include <gsl/gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstdint>
#include <vector>

namespace Tanker
{
namespace Streams
{
class PeekableInputSource
{
public:
  static constexpr std::uint64_t chunkSize = 1024;

  explicit PeekableInputSource(InputSource source);

  tc::cotask<gsl::span<std::uint8_t const>> peek(std::uint64_t size);

  tc::cotask<std::int64_t> operator()(gsl::span<std::uint8_t> buffer);

private:
  std::vector<std::uint8_t> _buffer;
  std::uint64_t _pos = 0;

  InputSource _underlyingStream;

  tc::cotask<void> fillBuffer(std::uint64_t bytesNeeded);
};
}
}
