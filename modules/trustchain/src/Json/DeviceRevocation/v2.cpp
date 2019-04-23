#include <Tanker/Trustchain/Actions/DeviceRevocation/v2.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void to_json(nlohmann::json& j, DeviceRevocation2 const& dr)
{
  j["deviceId"] = dr.deviceId();
  j["publicEncryptionKey"] = dr.publicEncryptionKey();
  j["previousPublicEncryptionKey"] = dr.previousPublicEncryptionKey();
  j["sealedKeyForPreviousUserKey"] = dr.sealedKeyForPreviousUserKey();
  j["sealedUserKeysForDevices"] = dr.sealedUserKeysForDevices();
}
}
}
}
