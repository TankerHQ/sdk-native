#pragma once

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Types/DeviceId.hpp>

#include <optional.hpp>

#include <cstdint>

namespace Tanker
{
struct Device
{
  DeviceId id;
  uint64_t createdAtBlkIndex;
  nonstd::optional<uint64_t> revokedAtBlkIndex;
  Crypto::PublicSignatureKey publicSignatureKey;
  Crypto::PublicEncryptionKey publicEncryptionKey;
  bool isGhostDevice;
};

bool operator==(Device const& l, Device const& r);
bool operator!=(Device const& l, Device const& r);
}
