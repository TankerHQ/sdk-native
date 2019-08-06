#pragma once

#include <Tanker/StreamInputSource.hpp>

#include <gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace Tanker
{
template <typename Derived>
class BufferedStream
{
public:
  explicit BufferedStream(StreamInputSource);

  tc::cotask<std::int64_t> operator()(std::uint8_t* out, std::int64_t n);

protected:
  // returns a view to the read input, which size can be at most n
  tc::cotask<gsl::span<std::uint8_t const>> readInputSource(std::int64_t n);
  // sets the state to BufferedOutput
  gsl::span<std::uint8_t> prepareWrite(std::int64_t toWrite);

private:
  enum class State
  {
    BufferedOutput,
    NoOutput,
    EndOfStream,
    Error,
  };

  tc::cotask<std::int64_t> copyBufferedOutput(std::uint8_t* out,
                                              std::int64_t n);

  StreamInputSource _cb;
  std::vector<std::uint8_t> _input;
  std::vector<std::uint8_t> _output;
  State _state{State::NoOutput};
  std::int64_t _currentPosition{};
};
}

#include <Tanker/Detail/BufferedStreamImpl.hpp>
