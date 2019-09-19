#include <Tanker/Streams/Helpers.hpp>

#include <algorithm>

namespace Tanker
{
namespace Streams
{
namespace
{
template <typename T>
InputSource bufferToInputSourceImpl(T&& buffer)
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

InputSource bufferViewToInputSource(gsl::span<uint8_t const> buffer)
{
  return bufferToInputSourceImpl(buffer);
}

InputSource bufferToInputSource(std::vector<uint8_t> buffer)
{
  return bufferToInputSourceImpl(std::move(buffer));
}
}
}
