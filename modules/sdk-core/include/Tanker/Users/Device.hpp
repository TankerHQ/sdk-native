#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <cstdint>
#include <optional>

namespace Tanker::Users
{
class Device
{
public:
  Device() = default;
  Device(Trustchain::DeviceId const& id,
         Trustchain::UserId const& userId,
         std::uint64_t createdAtBlkIndex,
         bool isGhostDevice,
         Crypto::PublicSignatureKey const& publicSignatureKey,
         Crypto::PublicEncryptionKey const& publicEncryptionKey);

  Device(Trustchain::DeviceId const& id,
         Trustchain::UserId const& userId,
         std::uint64_t createdAtBlkIndex,
         bool isGhostDevice,
         std::optional<std::uint64_t> revokedAtBlkIndex,
         Crypto::PublicSignatureKey const& publicSignatureKey,
         Crypto::PublicEncryptionKey const& publicEncryptionKey);

  Trustchain::DeviceId const& id() const;
  Trustchain::UserId const& userId() const;
  std::uint64_t const& createdAtBlkIndex() const;
  bool const& isGhostDevice() const;
  std::optional<std::uint64_t> const& revokedAtBlkIndex() const;
  void setRevokedAtBlkIndex(std::uint64_t index);
  Crypto::PublicSignatureKey const& publicSignatureKey() const;
  Crypto::PublicEncryptionKey const& publicEncryptionKey() const;

private:
  Trustchain::DeviceId _id;
  Trustchain::UserId _userId;
  std::uint64_t _createdAtBlkIndex;
  bool _isGhostDevice;
  std::optional<std::uint64_t> _revokedAtBlkIndex;
  Crypto::PublicSignatureKey _publicSignatureKey;
  Crypto::PublicEncryptionKey _publicEncryptionKey;
};

bool operator==(Device const& l, Device const& r);
bool operator!=(Device const& l, Device const& r);
bool operator<(Device const& l, Device const& r);
}
