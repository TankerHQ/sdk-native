#pragma once

#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>

#include <stdexcept>
#include <utility>

namespace Tanker
{
template <typename Derived>
BufferedStream<Derived>::BufferedStream(StreamInputSource cb)
  : _cb(std::move(cb))
{
}

template <typename Derived>
tc::cotask<std::int64_t> BufferedStream<Derived>::copyBufferedOutput(
    std::uint8_t* out, std::int64_t n)
{
  auto const toRead =
      std::min<std::int64_t>(n, _output.size() - _currentPosition);
  std::copy_n(_output.begin() + _currentPosition, toRead, out);
  _currentPosition += toRead;
  if (_currentPosition == static_cast<std::int64_t>(_output.size()))
  {
    if (_cb)
      _state = State::NoOutput;
    else
      _state = State::EndOfStream;
  }
  TC_RETURN(toRead);
}

template <typename Derived>
tc::cotask<gsl::span<std::uint8_t const>>
BufferedStream<Derived>::readInputSource(std::int64_t n)
{
  _input.resize(n);
  auto totalRead = 0l;
  while (totalRead != n)
  {
    auto const nbRead = TC_AWAIT(_cb(_input.data() + totalRead, n - totalRead));
    if (nbRead == 0)
      break;
    totalRead += nbRead;
  }
  if (totalRead < n)
    _cb = nullptr;
  _input.resize(totalRead);
  TC_RETURN(gsl::make_span(_input).template as_span<std::uint8_t const>());
}

template <typename Derived>
gsl::span<std::uint8_t> BufferedStream<Derived>::prepareWrite(
    std::int64_t toWrite)
{
  _output.resize(toWrite);
  _state = State::BufferedOutput;
  return gsl::make_span(_output);
}

template <typename Derived>
tc::cotask<std::int64_t> BufferedStream<Derived>::operator()(std::uint8_t* out,
                                                             std::int64_t n)
{
  using namespace Errors;

  try
  {
    switch (_state)
    {
    case State::EndOfStream:
      TC_RETURN(0);
    case State::Error:
      throw Exception(make_error_code(Errc::IOError),
                      "buffered stream is in an error state");
    case State::NoOutput:
      TC_AWAIT(static_cast<Derived&>(*this).processInput());
      _state = State::BufferedOutput;
      _currentPosition = 0;
      // fallthrough
    case State::BufferedOutput:
      TC_RETURN(TC_AWAIT(copyBufferedOutput(out, n)));
    }
  }
  catch (std::exception const&)
  {
    _cb = nullptr;
    _state = State::Error;
    throw;
  }
  throw AssertionError("unknown state");
}
}
