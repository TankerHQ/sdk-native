#include <Tanker/StreamHelpers.hpp>

namespace Tanker
{
namespace
{
template <typename T>
Streams::InputSource bufferToInputSourceImpl(T&& buffer)
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

Streams::InputSource bufferViewToInputSource(gsl::span<uint8_t const> buffer)
{
  return bufferToInputSourceImpl(buffer);
}

Streams::InputSource bufferToInputSource(std::vector<uint8_t> buffer)
{
  return bufferToInputSourceImpl(std::move(buffer));
}
}
