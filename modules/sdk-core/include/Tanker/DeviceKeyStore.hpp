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
class ADatabase;
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
      DataStore::ADatabase* dbConn);
  // for tests
  static tc::cotask<std::unique_ptr<DeviceKeyStore>> open(
      DataStore::ADatabase* dbConn, DeviceKeys const& keys);

private:
  DataStore::ADatabase* _db;
  DeviceKeys _keys;

  DeviceKeyStore(DataStore::ADatabase* dbConn);
};
}
