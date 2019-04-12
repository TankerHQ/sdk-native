#pragma once

#include <Tanker/Crypto/PrivateEncryptionKey.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Types/DeviceId.hpp>

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
struct GhostDevice
{
  DeviceId deviceId;
  Crypto::PrivateSignatureKey privateSignatureKey;
  Crypto::PrivateEncryptionKey privateEncryptionKey;
};

void from_json(nlohmann::json const& j, GhostDevice& d);
void to_json(nlohmann::json& j, GhostDevice const& d);

bool operator==(GhostDevice const& l, GhostDevice const& r);
bool operator!=(GhostDevice const& l, GhostDevice const& r);
}
