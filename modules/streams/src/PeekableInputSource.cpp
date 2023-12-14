#include <Tanker/Streams/PeekableInputSource.hpp>

#include <algorithm>

namespace Tanker
{
namespace Streams
{
constexpr const std::uint64_t PeekableInputSource::chunkSize;

PeekableInputSource::PeekableInputSource(InputSource source) : _underlyingStream(std::move(source))
{
}

tc::cotask<gsl::span<std::uint8_t const>> PeekableInputSource::peek(std::uint64_t size)
{
  auto const bytesAvailable = _buffer.size() - _pos;
  if (size > bytesAvailable)
    TC_AWAIT(fillBuffer(size - bytesAvailable));

  auto const availableToRead = gsl::make_span(_buffer).subspan(_pos);
  auto const result = availableToRead.subspan(0, std::min<std::uint64_t>(availableToRead.size(), size));
  TC_RETURN(result);
}

tc::cotask<void> PeekableInputSource::fillBuffer(std::uint64_t bytesNeeded)
{
  auto const writePos = _buffer.size();
  // If only a few bytes are needed, buffer a whole chunk to avoid repeated
  // reads
  auto const bytesToAsk = std::max<std::uint64_t>(bytesNeeded, chunkSize);
  _buffer.resize(_buffer.size() + bytesToAsk);
  auto toFill = gsl::make_span(_buffer).subspan(writePos);
  uint64_t totalRead = 0;
  // Read only what we need, it's ok if we don't fill a whole chunk
  while (totalRead < bytesNeeded)
  {
    auto const nbRead = TC_AWAIT(_underlyingStream(toFill));
    if (!nbRead)
      break;
    toFill = toFill.subspan(nbRead);
    totalRead += nbRead;
  }
  // Truncate the part we couldn't fill
  _buffer.resize(_buffer.size() - toFill.size());
}

tc::cotask<std::int64_t> PeekableInputSource::operator()(gsl::span<std::uint8_t> buffer)
{
  if (!_buffer.empty())
  {
    auto const toRead = std::min<std::uint64_t>(buffer.size(), _buffer.size() - _pos);
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
