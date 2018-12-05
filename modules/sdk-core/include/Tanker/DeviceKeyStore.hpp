#pragma once

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Types/DeviceId.hpp>

#include <tconcurrent/coroutine.hpp>

#include <memory>

namespace Tanker
{
namespace DataStore
{
class Database;
}

class DeviceKeyStore
{
public:
  DeviceKeyStore(DeviceKeyStore const&) = delete;
  DeviceKeyStore(DeviceKeyStore&&) = delete;
  DeviceKeyStore& operator=(DeviceKeyStore const&) = delete;
  DeviceKeyStore& operator=(DeviceKeyStore&&) = delete;

  Crypto::SignatureKeyPair const& signatureKeyPair() const noexcept;
  Crypto::EncryptionKeyPair const& encryptionKeyPair() const noexcept;
  DeviceId const& deviceId() const noexcept;

  tc::cotask<void> setDeviceId(DeviceId const& deviceId);
  DeviceKeys const& deviceKeys() const;

  static tc::cotask<std::unique_ptr<DeviceKeyStore>> open(
      DataStore::Database* dbConn);
  // for tests
  static tc::cotask<std::unique_ptr<DeviceKeyStore>> open(
      DataStore::Database* dbConn, DeviceKeys const& keys);

private:
  DataStore::Database* _db;
  DeviceKeys _keys;

  DeviceKeyStore(DataStore::Database* dbConn);
};
}
