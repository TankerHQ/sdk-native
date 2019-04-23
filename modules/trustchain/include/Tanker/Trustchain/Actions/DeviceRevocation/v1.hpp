#pragma once

#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class DeviceRevocation1
{
public:
  static constexpr auto const nature =
      Trustchain::Actions::Nature::DeviceRevocation;

  DeviceRevocation1() = default;
  explicit DeviceRevocation1(DeviceId const&);

  DeviceId const& deviceId() const;

private:
  DeviceId _deviceId;

  friend void from_serialized(Serialization::SerializedSource&,
                              DeviceRevocation1&);
};

bool operator==(DeviceRevocation1 const& lhs, DeviceRevocation1 const& rhs);
bool operator!=(DeviceRevocation1 const& lhs, DeviceRevocation1 const& rhs);
}
}
}

#include <Tanker/Trustchain/Json/DeviceRevocation/v1.hpp>
#include <Tanker/Trustchain/Serialization/DeviceRevocation/v1.hpp>
