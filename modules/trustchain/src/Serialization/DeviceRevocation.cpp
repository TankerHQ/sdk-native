#include <Tanker/Trustchain/Serialization/DeviceRevocation.hpp>

#include <Tanker/Serialization/Serialization.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
std::uint8_t* to_serialized(std::uint8_t* it, DeviceRevocation const& dc)
{
  return Serialization::serialize(it, dc._variant);
}

std::size_t serialized_size(DeviceRevocation const& dc)
{
  return Serialization::serialized_size(dc._variant);
}
}
}
}
