#include <Tanker/Streams/PeekableInputSource.hpp>

#include <algorithm>

namespace Tanker
{
namespace Streams
{
constexpr const std::uint64_t PeekableInputSource::chunkSize;

PeekableInputSource::PeekableInputSource(InputSource source)
  : _underlyingStream(std::move(source))
{
}

tc::cotask<gsl::span<std::uint8_t const>> PeekableInputSource::peek(
    std::uint64_t size)
{
  auto const needed = size - (_buffer.size() - _pos);
  auto const toAsk = std::max<std::uint64_t>(needed, chunkSize);
  auto writePos = _buffer.size();
  while (writePos - _pos < size)
  {
    _buffer.resize(writePos + toAsk);
    auto const nbRead = TC_AWAIT(
        _underlyingStream(gsl::make_span(_buffer.data() + writePos, toAsk)));
    if (!nbRead)
      break;
    writePos += nbRead;
  }
  _buffer.resize(writePos);
  TC_RETURN(gsl::make_span<std::uint8_t const>(
      _buffer.data() + _pos, std::min<std::uint64_t>(size, writePos - _pos)));
}

tc::cotask<std::int64_t> PeekableInputSource::operator()(
    gsl::span<std::uint8_t> buffer)
{
  if (!_buffer.empty())
  {
    auto const toRead =
        std::min<std::uint64_t>(buffer.size(), _buffer.size() - _pos);
    std::copy_n(_buffer.begin() + _pos, toRead, buffer.data());
    _pos += toRead;
    if (_pos == _buffer.size())
    {
      _buffer.clear();
      _pos = 0;
    }
    TC_RETURN(toRead);
  }
  else
  {
    TC_RETURN(TC_AWAIT(_underlyingStream(buffer)));
  }
}
}
}
