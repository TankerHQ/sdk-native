#pragma once

#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Json.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Serialization.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
#define TANKER_TRUSTCHAIN_ACTIONS_DEVICE_REVOCATION_V1_ATTRIBUTES \
  (deviceId, DeviceId)

class DeviceRevocation1
{
public:
  TANKER_IMMUTABLE_DATA_TYPE_IMPLEMENTATION(
      DeviceRevocation1,
      TANKER_TRUSTCHAIN_ACTIONS_DEVICE_REVOCATION_V1_ATTRIBUTES)
public:
  static constexpr Nature nature();

private:
  friend void from_serialized(Serialization::SerializedSource&,
                              DeviceRevocation1&);
};

constexpr Nature DeviceRevocation1::nature()
{
  return Nature::DeviceRevocation;
}

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(DeviceRevocation1)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(DeviceRevocation1)
}
}
}
