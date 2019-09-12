#include <Tanker/PeekableInputSource.hpp>

namespace Tanker
{
constexpr const uint64_t PeekableInputSource::chunkSize;

PeekableInputSource::PeekableInputSource(StreamInputSource source)
  : _underlyingStream(std::move(source))
{
}

tc::cotask<gsl::span<uint8_t const>> PeekableInputSource::peek(uint64_t size)
{
  auto const needed = size - (_buffer.size() - _pos);
  auto const toAsk = std::max<uint64_t>(needed, chunkSize);
  auto writePos = _buffer.size();
  while (writePos - _pos < size)
  {
    _buffer.resize(writePos + toAsk);
    auto const nbRead =
        TC_AWAIT(_underlyingStream(_buffer.data() + writePos, toAsk));
    if (!nbRead)
      break;
    writePos += nbRead;
  }
  _buffer.resize(writePos);
  TC_RETURN(gsl::make_span<uint8_t const>(
      _buffer.data() + _pos, std::min<uint64_t>(size, writePos - _pos)));
}

tc::cotask<int64_t> PeekableInputSource::operator()(uint8_t* buffer,
                                                    size_t size)
{
  if (!_buffer.empty())
  {
    auto const toRead = std::min<uint64_t>(size, _buffer.size() - _pos);
    std::copy_n(_buffer.begin() + _pos, toRead, buffer);
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
    TC_RETURN(TC_AWAIT(_underlyingStream(buffer, size)));
  }
}
}
