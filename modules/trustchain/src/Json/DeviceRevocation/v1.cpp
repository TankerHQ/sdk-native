#include <Tanker/Trustchain/Actions/DeviceRevocation/v1.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void to_json(nlohmann::json& j, DeviceRevocation1 const& dr)
{
  j["deviceId"] = dr.deviceId();
}
}
}
}
