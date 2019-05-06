#include <Tanker/Trustchain/Actions/DeviceRevocation/v1.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
DeviceRevocation1::DeviceRevocation1(DeviceId const& deviceId)
  : _deviceId(deviceId)
{
}

DeviceId const& DeviceRevocation1::deviceId() const
{
  return _deviceId;
}

bool operator==(DeviceRevocation1 const& lhs, DeviceRevocation1 const& rhs)
{
  return lhs.deviceId() == rhs.deviceId();
}

bool operator!=(DeviceRevocation1 const& lhs, DeviceRevocation1 const& rhs)
{
  return !(lhs == rhs);
}

void from_serialized(Serialization::SerializedSource& ss, DeviceRevocation1& dr)
{
  Serialization::deserialize_to(ss, dr._deviceId);
}

std::uint8_t* to_serialized(std::uint8_t* it, DeviceRevocation1 const& dr)
{
  return Serialization::serialize(it, dr.deviceId());
}

void to_json(nlohmann::json& j, DeviceRevocation1 const& dr)
{
  j["deviceId"] = dr.deviceId();
}
}
}
}
