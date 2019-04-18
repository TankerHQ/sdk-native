#include <Tanker/Trustchain/Serialization/DeviceCreation.hpp>

#include <Tanker/Serialization/Serialization.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
std::uint8_t* to_serialized(std::uint8_t* it, DeviceCreation const& dc)
{
  return Serialization::serialize(it, dc._variant);
}

std::size_t serialized_size(DeviceCreation const& dc)
{
  return Serialization::serialized_size(dc._variant);
}
}
}
}
