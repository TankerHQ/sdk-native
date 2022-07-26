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
             gsl::span<std::uint8_t> out) mutable -> tc::cotask<std::int64_t> {
    auto const toRead =
        std::min<std::uint64_t>(out.size(), buffer.size() - index);
    std::copy_n(buffer.data() + index, toRead, out.data());
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
