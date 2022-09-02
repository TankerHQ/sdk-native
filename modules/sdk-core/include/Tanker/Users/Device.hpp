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
         Crypto::PublicSignatureKey const& publicSignatureKey,
         Crypto::PublicEncryptionKey const& publicEncryptionKey,
         bool isGhostDevice);

  Trustchain::DeviceId const& id() const;
  Trustchain::UserId const& userId() const;
  bool const& isGhostDevice() const;
  Crypto::PublicSignatureKey const& publicSignatureKey() const;
  Crypto::PublicEncryptionKey const& publicEncryptionKey() const;

private:
  Trustchain::DeviceId _id;
  Trustchain::UserId _userId;
  Crypto::PublicSignatureKey _publicSignatureKey;
  Crypto::PublicEncryptionKey _publicEncryptionKey;
  bool _isGhostDevice;
};

bool operator==(Device const& l, Device const& r);
bool operator!=(Device const& l, Device const& r);
bool operator<(Device const& l, Device const& r);
}
