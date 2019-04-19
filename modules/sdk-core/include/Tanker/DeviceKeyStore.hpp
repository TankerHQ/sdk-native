#pragma once

#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>

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
  Trustchain::DeviceId const& deviceId() const noexcept;

  tc::cotask<void> setDeviceId(Trustchain::DeviceId const& deviceId);
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
