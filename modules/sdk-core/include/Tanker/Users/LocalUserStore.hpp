#pragma once

#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/DataStore/Backend.hpp>
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
struct DeviceData
{
  Crypto::PublicSignatureKey trustchainPublicKey;
  Trustchain::DeviceId deviceId;
  DeviceKeys deviceKeys;
  std::vector<Crypto::EncryptionKeyPair> userKeys;
};

class LocalUserStore
{
public:
  LocalUserStore(Crypto::SymmetricKey const& userSecret, DataStore::DataStore* db);

  tc::cotask<void> initializeDevice(Crypto::PublicSignatureKey const& trustchainPublicKey,
                                    Trustchain::DeviceId const& deviceId,
                                    DeviceKeys const& deviceKeys,
                                    std::vector<Crypto::EncryptionKeyPair> const& userKeys);

  tc::cotask<void> putUserKeys(std::vector<Crypto::EncryptionKeyPair> userKeys);

  tc::cotask<std::optional<Crypto::PublicSignatureKey>> findTrustchainPublicSignatureKey() const;
  tc::cotask<std::optional<LocalUser>> findLocalUser(Trustchain::UserId const& userId) const;
  tc::cotask<DeviceKeys> getDeviceKeys() const;
  tc::cotask<Trustchain::DeviceId> getDeviceId() const;
  tc::cotask<std::optional<DeviceKeys>> findDeviceKeys() const;

private:
  tc::cotask<void> setDeviceData(DeviceData const& deviceData);
  tc::cotask<std::optional<DeviceData>> getDeviceData() const;
  tc::cotask<std::vector<Crypto::EncryptionKeyPair>> getUserKeyPairs() const;

  Crypto::SymmetricKey _userSecret;

  DataStore::DataStore* _db;
};
}
}
