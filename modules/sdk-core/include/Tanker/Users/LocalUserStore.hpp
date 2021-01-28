#pragma once

#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/LocalUser.hpp>

#include <gsl/gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <optional>

namespace Tanker
{
struct DeviceKeys;

namespace DataStore
{
class Database;
}

namespace Users
{
class LocalUserStore
{
public:
  LocalUserStore(DataStore::Database* dbCon);

  tc::cotask<void> initializeDevice(
      Crypto::PublicSignatureKey const& trustchaniPublicKey,
      Trustchain::DeviceId const& deviceId,
      DeviceKeys const& deviceKeys,
      std::vector<Crypto::EncryptionKeyPair> const& userKeys);

  tc::cotask<void> putUserKeys(
      gsl::span<Crypto::EncryptionKeyPair const> userKeys);

  tc::cotask<std::optional<Crypto::PublicSignatureKey>>
  findTrustchainPublicSignatureKey() const;
  tc::cotask<std::optional<LocalUser>> findLocalUser(
      Trustchain::UserId const& userId) const;
  tc::cotask<DeviceKeys> getDeviceKeys() const;
  tc::cotask<Trustchain::DeviceId> getDeviceId() const;
  tc::cotask<std::optional<DeviceKeys>> findDeviceKeys() const;

private:
  tc::cotask<void> setTrustchainPublicSignatureKey(
      Crypto::PublicSignatureKey const& sigKey);
  tc::cotask<void> setDeviceData(Trustchain::DeviceId const& deviceId,
                                 DeviceKeys const& deviceKeys);
  tc::cotask<std::vector<Crypto::EncryptionKeyPair>> getUserKeyPairs() const;

  DataStore::Database* _db;
};
}
}
