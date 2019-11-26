#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <optional>

#include <cstdint>

namespace Tanker
{
struct Device
{
  Device() = default;
  Trustchain::DeviceId id;
  Trustchain::UserId userId;
  uint64_t createdAtBlkIndex = 0;
  std::optional<uint64_t> revokedAtBlkIndex;
  Crypto::PublicSignatureKey publicSignatureKey;
  Crypto::PublicEncryptionKey publicEncryptionKey;
  bool isGhostDevice = false;
};

bool operator==(Device const& l, Device const& r);
bool operator!=(Device const& l, Device const& r);
}
