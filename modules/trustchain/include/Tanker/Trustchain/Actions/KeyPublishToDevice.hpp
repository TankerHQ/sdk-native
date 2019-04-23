#pragma once

#include <Tanker/Crypto/EncryptedSymmetricKey.hpp>
#include <Tanker/Crypto/Mac.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class KeyPublishToDevice
{
public:
  KeyPublishToDevice() = default;
  KeyPublishToDevice(DeviceId const&,
                     Crypto::Mac const&,
                     Crypto::EncryptedSymmetricKey const&);

  constexpr Nature nature() const;

  DeviceId const& recipient() const;
  Crypto::Mac const& mac() const;
  Crypto::EncryptedSymmetricKey const& encryptedSymmetricKey() const;

private:
  DeviceId _recipient;
  Crypto::Mac _mac;
  Crypto::EncryptedSymmetricKey _key;

  friend void from_serialized(Serialization::SerializedSource&,
                              KeyPublishToDevice&);
};

bool operator==(KeyPublishToDevice const&, KeyPublishToDevice const&);
bool operator!=(KeyPublishToDevice const&, KeyPublishToDevice const&);

constexpr Nature KeyPublishToDevice::nature() const
{
  return Nature::KeyPublishToDevice;
}
}
}
}

#include <Tanker/Trustchain/Json/KeyPublishToDevice.hpp>
#include <Tanker/Trustchain/Serialization/KeyPublishToDevice.hpp>
