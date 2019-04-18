#include <Tanker/Trustchain/Actions/DeviceCreation/v2.hpp>

#include <Tanker/Serialization/Serialization.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void from_serialized(Serialization::SerializedSource& ss, DeviceCreation2& dc)
{
  Serialization::deserialize_to(ss, dc._lastReset);
  Serialization::deserialize_to(ss, static_cast<DeviceCreation1&>(dc));
}

std::uint8_t* to_serialized(std::uint8_t* it, DeviceCreation2 const& dc)
{
  it = Serialization::serialize(it, dc.lastReset());
  return Serialization::serialize(it, static_cast<DeviceCreation1 const&>(dc));
}
}
}
}
