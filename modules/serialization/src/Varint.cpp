#include <Tanker/Serialization/Varint.hpp>

#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Errors/Errc.hpp>

namespace Tanker
{
namespace Serialization
{
std::pair<std::uint32_t, gsl::span<uint8_t const>> varint_read(gsl::span<uint8_t const> data)
try
{
  std::uint32_t value = 0;
  std::uint32_t factor = 1;
  while ((data[0] & 0x80) != 0)
  {
    value += (data[0] & 0x7f) * factor;
    factor *= 128;
    data = data.subspan(1);
  }
  value += data[0] * factor;
  data = data.subspan(1);
  return {value, data};
}
catch (gsl::fail_fast const&)
{
  throw Errors::Exception(Errc::TruncatedInput, "Could not read varint");
}

std::uint8_t* varint_write(std::uint8_t* it, std::uint32_t value)
{
  while (value > 127)
  {
    *it++ = (0x80 | value);
    value /= 128;
  }
  *it++ = value;
  return it;
}
}
}
