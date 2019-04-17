#include <Tanker/Trustchain/Actions/DeviceCreation/v3.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void to_json(nlohmann::json& j, DeviceCreation3 const& dc)
{
  j = static_cast<DeviceCreation1 const&>(dc);
  j["userKeyPair"]["publicEncryptionKey"] = dc.publicUserEncryptionKey();
  j["userKeyPair"]["encryptedPrivateEncryptionKey"] =
      dc.sealedPrivateUserEncryptionKey();
  j["is_ghost_device"] = dc.isGhostDevice();
}
}
}
}
