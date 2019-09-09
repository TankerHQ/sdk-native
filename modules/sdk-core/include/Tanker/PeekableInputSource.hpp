#pragma once

#include <Tanker/StreamInputSource.hpp>

#include <tconcurrent/coroutine.hpp>

#include <gsl-lite.hpp>

#include <cstdint>
#include <vector>

namespace Tanker
{
class PeekableInputSource
{
public:
  static constexpr uint64_t chunkSize = 1024;

  explicit PeekableInputSource(StreamInputSource source);

  tc::cotask<gsl::span<uint8_t const>> peek(uint64_t size);

  tc::cotask<int64_t> operator()(uint8_t* buffer, size_t size);

private:
  std::vector<uint8_t> _buffer;
  uint64_t _pos = 0;

  StreamInputSource _underlyingStream;
};
}
