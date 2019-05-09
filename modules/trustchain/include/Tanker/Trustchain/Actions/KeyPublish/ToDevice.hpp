#pragma once

#include <Tanker/Crypto/EncryptedSymmetricKey.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Serialization/Varint.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>

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

void from_serialized(Serialization::SerializedSource&, KeyPublishToDevice&);
std::uint8_t* to_serialized(std::uint8_t*, KeyPublishToDevice const&);

constexpr std::size_t serialized_size(KeyPublishToDevice const&)
{
  return DeviceId::arraySize + ResourceId::arraySize +
         Serialization::varint_size(Crypto::EncryptedSymmetricKey::arraySize) +
         Crypto::EncryptedSymmetricKey::arraySize;
}

void to_json(nlohmann::json&, KeyPublishToDevice const&);

constexpr Nature KeyPublishToDevice::nature()
{
  return Nature::KeyPublishToDevice;
}
}
}
}
