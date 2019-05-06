#include <Tanker/Trustchain/Actions/DeviceRevocation/v1.hpp>

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
}
}
}
