#pragma once

#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class DeviceRevocation1
{
public:
  static constexpr Nature nature();

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

void from_serialized(Serialization::SerializedSource&, DeviceRevocation1&);

std::uint8_t* to_serialized(std::uint8_t*, DeviceRevocation1 const&);

constexpr std::size_t serialized_size(DeviceRevocation1 const&)
{
  return DeviceId::arraySize;
}

void to_json(nlohmann::json&, DeviceRevocation1 const&);

constexpr Nature DeviceRevocation1::nature()
{
  return Nature::DeviceRevocation;
}
}
}
}
