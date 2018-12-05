#include <Tanker/GhostDevice.hpp>

#include <Tanker/Crypto/JsonFormat.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Types/DeviceId.hpp>

#include <nlohmann/json.hpp>

#include <tuple>

namespace Tanker
{
void from_json(nlohmann::json const& j, GhostDevice& d)
{
  j.at("deviceId").get_to(d.deviceId);
  j.at("privateSignatureKey").get_to(d.privateSignatureKey);
  j.at("privateEncryptionKey").get_to(d.privateEncryptionKey);
}

void to_json(nlohmann::json& j, GhostDevice const& d)
{
  j["deviceId"] = d.deviceId;
  j["privateSignatureKey"] = d.privateSignatureKey;
  j["privateEncryptionKey"] = d.privateEncryptionKey;
}

bool operator==(GhostDevice const& l, GhostDevice const& r)
{
  return std::tie(l.deviceId, l.privateSignatureKey, l.privateEncryptionKey) ==
         std::tie(r.deviceId, r.privateSignatureKey, r.privateEncryptionKey);
}

bool operator!=(GhostDevice const& l, GhostDevice const& r)
{
  return !(l == r);
}
}
