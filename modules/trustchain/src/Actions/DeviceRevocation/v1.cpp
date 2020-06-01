#include <Tanker/Trustchain/Actions/DeviceRevocation/v1.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
TANKER_TRUSTCHAIN_ACTION_DEFINE_SERIALIZATION(
    DeviceRevocation1,
    TANKER_TRUSTCHAIN_ACTIONS_DEVICE_REVOCATION_V1_ATTRIBUTES)
TANKER_TRUSTCHAIN_ACTION_DEFINE_TO_JSON(
    DeviceRevocation1,
    TANKER_TRUSTCHAIN_ACTIONS_DEVICE_REVOCATION_V1_ATTRIBUTES)
}
}
}
