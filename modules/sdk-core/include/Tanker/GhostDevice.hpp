#pragma once

#include <Tanker/Crypto/PrivateEncryptionKey.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Types/VerificationKey.hpp>

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
struct GhostDevice
{
  Crypto::PrivateSignatureKey privateSignatureKey;
  Crypto::PrivateEncryptionKey privateEncryptionKey;
  static GhostDevice create(VerificationKey const& key);
  static GhostDevice create(
      DeviceKeys const& deviceKeys = DeviceKeys::create());
  DeviceKeys toDeviceKeys() const;
  VerificationKey toVerificationKey() const;
};

void from_json(nlohmann::json const& j, GhostDevice& d);
void to_json(nlohmann::json& j, GhostDevice const& d);

bool operator==(GhostDevice const& l, GhostDevice const& r);
bool operator!=(GhostDevice const& l, GhostDevice const& r);
}
