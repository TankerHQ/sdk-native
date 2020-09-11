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

  tc::cotask<bool> isInitialized();
  tc::cotask<void> setDeviceId(Trustchain::DeviceId const& deviceId);

  tc::cotask<void> putLocalUser(LocalUser const& user);
  tc::cotask<void> putUserKeys(
      gsl::span<Crypto::EncryptionKeyPair const> userKeys);

  tc::cotask<std::optional<Crypto::PublicSignatureKey>>
  findTrustchainPublicSignatureKey() const;
  tc::cotask<void> setTrustchainPublicSignatureKey(
      Crypto::PublicSignatureKey const& sigKey);
  tc::cotask<std::optional<LocalUser>> findLocalUser(
      Trustchain::UserId const& userId) const;
  tc::cotask<DeviceKeys> getDeviceKeys() const;
  tc::cotask<Trustchain::DeviceId> getDeviceId() const;
  tc::cotask<std::optional<DeviceKeys>> findDeviceKeys() const;
  // TODO put in private
  tc::cotask<void> setDeviceKeys(DeviceKeys const& deviceKeys);

private:
  tc::cotask<std::vector<Crypto::EncryptionKeyPair>> getUserKeyPairs() const;
  tc::cotask<void> setDeviceInitialized();
  tc::cotask<bool> isDeviceInitialized() const;

  DataStore::Database* _db;
};
}
}
