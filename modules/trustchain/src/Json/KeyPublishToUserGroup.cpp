#include <Tanker/Trustchain/Actions/KeyPublishToUserGroup.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void to_json(nlohmann::json& j, KeyPublishToUserGroup const& kp)
{
  j["recipientPublicEncryptionKey"] = kp.recipientPublicEncryptionKey();
  j["mac"] = kp.mac();
  j["key"] = kp.sealedSymmetricKey();
}
}
}
}
