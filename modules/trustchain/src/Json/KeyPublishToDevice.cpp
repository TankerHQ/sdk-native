#include <Tanker/Trustchain/Actions/KeyPublishToDevice.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void to_json(nlohmann::json& j, KeyPublishToDevice const& kp)
{
  j["recipient"] = kp.recipient();
  j["resourceId"] = kp.resourceId();
  j["key"] = kp.encryptedSymmetricKey();
}
}
}
}
