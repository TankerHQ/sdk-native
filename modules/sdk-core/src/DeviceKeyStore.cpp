#include <Tanker/DeviceKeyStore.hpp>

#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>

#include <memory>
#include <stdexcept>
#include <utility>

namespace Tanker
{
tc::cotask<std::unique_ptr<DeviceKeyStore>> DeviceKeyStore::open(
    DataStore::ADatabase* dbConn)
{
  std::unique_ptr<DeviceKeyStore> deviceKeyStore(new DeviceKeyStore(dbConn));

  auto const keys = TC_AWAIT(dbConn->getDeviceKeys());

  if (keys)
  {
    deviceKeyStore->_keys = *keys;
    deviceKeyStore->_deviceId =
        TC_AWAIT(dbConn->getDeviceId()).value_or(Trustchain::DeviceId{});
  }
  else
  {
    deviceKeyStore->_keys = DeviceKeys::create();
    TC_AWAIT(dbConn->setDeviceKeys(deviceKeyStore->_keys));
  }

  TC_RETURN(std::move(deviceKeyStore));
}

tc::cotask<std::unique_ptr<DeviceKeyStore>> DeviceKeyStore::open(
    DataStore::ADatabase* dbConn, DeviceKeys const& keys)
{
  // FIXME blast this constructor and write tests correctly

  std::unique_ptr<DeviceKeyStore> deviceKeyStore(new DeviceKeyStore(dbConn));
  deviceKeyStore->_keys = keys;
  TC_AWAIT(dbConn->setDeviceKeys(deviceKeyStore->_keys));

  TC_RETURN(std::move(deviceKeyStore));
}

DeviceKeyStore::DeviceKeyStore(DataStore::ADatabase* dbConn)
  : _db(dbConn), _deviceId()
{
}

Crypto::SignatureKeyPair const& DeviceKeyStore::signatureKeyPair() const
    noexcept
{
  return _keys.signatureKeyPair;
}

Crypto::EncryptionKeyPair const& DeviceKeyStore::encryptionKeyPair() const
    noexcept
{
  return _keys.encryptionKeyPair;
}

Trustchain::DeviceId const& DeviceKeyStore::deviceId() const noexcept
{
  return _deviceId;
}

DeviceKeys const& DeviceKeyStore::deviceKeys() const
{
  return _keys;
}

tc::cotask<void> DeviceKeyStore::setDeviceId(
    Trustchain::DeviceId const& deviceId)
{
  if (!this->_deviceId.is_null() && deviceId != this->_deviceId)
    throw std::runtime_error("deviceId already set");
  TC_AWAIT(_db->setDeviceId(deviceId));
  _deviceId = deviceId;
}
}
