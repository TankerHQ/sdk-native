#include <Tanker/Trustchain/Actions/DeviceRevocation/v1.hpp>

#include <Tanker/Serialization/Serialization.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void from_serialized(Serialization::SerializedSource& ss, DeviceRevocation1& dr)
{
  Serialization::deserialize_to(ss, dr._deviceId);
}

std::uint8_t* to_serialized(std::uint8_t* it, DeviceRevocation1 const& dr)
{
  return Serialization::serialize(it, dr.deviceId());
}
}
}
}
