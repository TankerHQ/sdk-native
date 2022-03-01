#pragma once

#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Streams/Helpers.hpp>

#include <stdexcept>
#include <utility>

namespace Tanker
{
namespace Streams
{
template <typename Derived>
BufferedStream<Derived>::BufferedStream(InputSource cb) : _cb(std::move(cb))
{
}

template <typename Derived>
tc::cotask<std::int64_t> BufferedStream<Derived>::copyBufferedOutput(
    gsl::span<std::uint8_t> out)
{
  auto const toRead =
      std::min<std::int64_t>(out.size(), _output.size() - _currentPosition);
  std::copy_n(_output.begin() + _currentPosition, toRead, out.data());
  _currentPosition += toRead;
  if (_currentPosition == static_cast<std::int64_t>(_output.size()))
  {
    if (!_processingComplete)
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
  if (!_cb)
    TC_RETURN(gsl::span<std::uint8_t const>());

  _input.resize(n);
  auto const totalRead = TC_AWAIT(readStream(_input, _cb));
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
tc::cotask<std::int64_t> BufferedStream<Derived>::operator()(
    gsl::span<std::uint8_t> out)
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
      TC_RETURN(TC_AWAIT(copyBufferedOutput(out)));
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

template <typename Derived>
bool BufferedStream<Derived>::isInputEndOfStream()
{
  return !_cb;
}

template <typename Derived>
void BufferedStream<Derived>::endOutputStream()
{
  _processingComplete = true;
  _cb = nullptr;
}
}
}
