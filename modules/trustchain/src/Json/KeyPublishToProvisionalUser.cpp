#include <Tanker/Trustchain/Actions/KeyPublishToProvisionalUser.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void to_json(nlohmann::json& j, KeyPublishToProvisionalUser const& kp)
{
  j["appPublicSignatureKey"] = kp.appPublicSignatureKey();
  j["tankerPublicSignatureKey"] = kp.tankerPublicSignatureKey();
  j["resourceId"] = kp.resourceId();
  j["twoTimesSealedSymmetricKey"] = kp.twoTimesSealedSymmetricKey();
}
}
}
}
