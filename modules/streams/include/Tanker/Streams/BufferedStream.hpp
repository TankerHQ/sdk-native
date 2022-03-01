#pragma once

#include <Tanker/Streams/InputSource.hpp>

#include <gsl/gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace Tanker
{
namespace Streams
{
template <typename Derived>
class BufferedStream
{
public:
  explicit BufferedStream(InputSource);

  tc::cotask<std::int64_t> operator()(gsl::span<std::uint8_t> out);

protected:
  // returns a view to the read input, which size can be at most n
  tc::cotask<gsl::span<std::uint8_t const>> readInputSource(std::int64_t n);
  // sets the state to BufferedOutput
  gsl::span<std::uint8_t> prepareWrite(std::int64_t toWrite);

  bool isInputEndOfStream();
  void endOutputStream();

private:
  enum class State
  {
    BufferedOutput,
    NoOutput,
    EndOfStream,
    Error,
  };

  tc::cotask<std::int64_t> copyBufferedOutput(gsl::span<std::uint8_t> out);

  InputSource _cb;
  std::vector<std::uint8_t> _input;
  std::vector<std::uint8_t> _output;
  State _state{State::NoOutput};
  bool _processingComplete = false;
  std::int64_t _currentPosition{};
};
}
}

#include <Tanker/Streams/Detail/BufferedStreamImpl.hpp>
