#pragma once

#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <optional>

namespace Tanker::Users
{
class LocalUser
{
public:
  LocalUser(Trustchain::UserId const& userId,
            Trustchain::DeviceId const& deviceId,
            DeviceKeys const& deviceKeys,
            gsl::span<Crypto::EncryptionKeyPair const> userKeys);

  Trustchain::UserId const& userId() const;
  Trustchain::DeviceId const& deviceId() const;
  DeviceKeys const& deviceKeys() const;
  Crypto::EncryptionKeyPair currentKeyPair() const;
  std::optional<Crypto::EncryptionKeyPair> findKeyPair(
      Crypto::PublicEncryptionKey const& publicKey) const;
  std::vector<Crypto::EncryptionKeyPair> const& userKeys() const;

private:
  Trustchain::UserId _userId;
  Trustchain::DeviceId _deviceId;
  DeviceKeys _deviceKeys;
  std::vector<Crypto::EncryptionKeyPair> _userKeys;
};
}