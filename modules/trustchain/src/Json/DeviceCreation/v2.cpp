#include <Tanker/Trustchain/Actions/DeviceCreation/v2.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void to_json(nlohmann::json& j, DeviceCreation2 const& dc)
{
  j = static_cast<DeviceCreation1 const&>(dc);
  j["lastReset"] = dc.lastReset();
}
}
}
}
