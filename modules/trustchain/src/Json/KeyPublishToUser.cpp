#include <Tanker/Trustchain/Actions/KeyPublishToUser.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void to_json(nlohmann::json& j, KeyPublishToUser const& kp)
{
  j["recipientPublicEncryptionKey"] = kp.recipientPublicEncryptionKey();
  j["resourceId"] = kp.resourceId();
  j["key"] = kp.sealedSymmetricKey();
}
}
}
}
