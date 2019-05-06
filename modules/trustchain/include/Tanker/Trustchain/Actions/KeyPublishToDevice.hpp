#pragma once

#include <Tanker/Crypto/EncryptedSymmetricKey.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

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
                     ResourceId const&,
                     Crypto::EncryptedSymmetricKey const&);

  static constexpr Nature nature();

  DeviceId const& recipient() const;
  ResourceId const& resourceId() const;
  Crypto::EncryptedSymmetricKey const& encryptedSymmetricKey() const;

private:
  DeviceId _recipient;
  ResourceId _resourceId;
  Crypto::EncryptedSymmetricKey _key;

  friend void from_serialized(Serialization::SerializedSource&,
                              KeyPublishToDevice&);
};

bool operator==(KeyPublishToDevice const&, KeyPublishToDevice const&);
bool operator!=(KeyPublishToDevice const&, KeyPublishToDevice const&);

constexpr Nature KeyPublishToDevice::nature()
{
  return Nature::KeyPublishToDevice;
}
}
}
}

#include <Tanker/Trustchain/Json/KeyPublishToDevice.hpp>
#include <Tanker/Trustchain/Serialization/KeyPublishToDevice.hpp>
