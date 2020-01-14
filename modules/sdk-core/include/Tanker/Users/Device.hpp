#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <cstdint>
#include <optional>

namespace Tanker::Users
{
struct Device
{
  Device(Trustchain::DeviceId const& id,
         Trustchain::UserId const& userId,
         uint64_t createdAtBlkIndex,
         bool isGhostDevice,
         Crypto::PublicSignatureKey const& publicSignatureKey,
         Crypto::PublicEncryptionKey const& publicEncryptionKey);

  Device(Trustchain::DeviceId const& id,
         Trustchain::UserId const& userId,
         uint64_t createdAtBlkIndex,
         bool isGhostDevice,
         std::optional<uint64_t> revokedAtBlkIndex,
         Crypto::PublicSignatureKey const& publicSignatureKey,
         Crypto::PublicEncryptionKey const& publicEncryptionKey);

  Trustchain::DeviceId id;
  Trustchain::UserId userId;
  uint64_t createdAtBlkIndex;
  bool isGhostDevice;
  std::optional<uint64_t> revokedAtBlkIndex;
  Crypto::PublicSignatureKey publicSignatureKey;
  Crypto::PublicEncryptionKey publicEncryptionKey;
};
bool operator==(Device const& l, Device const& r);
bool operator!=(Device const& l, Device const& r);
bool operator<(Device const& l, Device const& r);
}
