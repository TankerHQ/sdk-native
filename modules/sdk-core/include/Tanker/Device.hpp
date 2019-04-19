#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>

#include <optional.hpp>

#include <cstdint>

namespace Tanker
{
struct Device
{
  Trustchain::DeviceId id;
  uint64_t createdAtBlkIndex;
  nonstd::optional<uint64_t> revokedAtBlkIndex;
  Crypto::PublicSignatureKey publicSignatureKey;
  Crypto::PublicEncryptionKey publicEncryptionKey;
  bool isGhostDevice;
};

bool operator==(Device const& l, Device const& r);
bool operator!=(Device const& l, Device const& r);
}
