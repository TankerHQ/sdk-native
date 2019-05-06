#include <Tanker/Trustchain/Actions/KeyPublishToDevice.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

#include <stdexcept>
#include <string>
#include <tuple>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
KeyPublishToDevice::KeyPublishToDevice(DeviceId const& recipient,
                                       ResourceId const& resourceId,
                                       Crypto::EncryptedSymmetricKey const& key)
  : _recipient(recipient), _resourceId(resourceId), _key(key)
{
}

DeviceId const& KeyPublishToDevice::recipient() const
{
  return _recipient;
}

ResourceId const& KeyPublishToDevice::resourceId() const
{
  return _resourceId;
}

Crypto::EncryptedSymmetricKey const& KeyPublishToDevice::encryptedSymmetricKey()
    const
{
  return _key;
}

bool operator==(KeyPublishToDevice const& lhs, KeyPublishToDevice const& rhs)
{
  return std::tie(
             lhs.recipient(), lhs.resourceId(), lhs.encryptedSymmetricKey()) ==
         std::tie(
             rhs.recipient(), rhs.resourceId(), rhs.encryptedSymmetricKey());
}

bool operator!=(KeyPublishToDevice const& lhs, KeyPublishToDevice const& rhs)
{
  return !(lhs == rhs);
}

void from_serialized(Serialization::SerializedSource& ss,
                     KeyPublishToDevice& kp)
{
  Serialization::deserialize_to(ss, kp._recipient);
  Serialization::deserialize_to(ss, kp._resourceId);
  auto const keySize = ss.read_varint();
  if (keySize != Crypto::EncryptedSymmetricKey::arraySize)
  {
    throw std::runtime_error("invalid size for encrypted key: " +
                             std::to_string(keySize));
  }
  Serialization::deserialize_to(ss, kp._key);
}

std::uint8_t* to_serialized(std::uint8_t* it, KeyPublishToDevice const& kp)
{
  it = Serialization::serialize(it, kp.recipient());
  it = Serialization::serialize(it, kp.resourceId());
  it = Serialization::varint_write(it, Crypto::EncryptedSymmetricKey::arraySize);
  return Serialization::serialize(it, kp.encryptedSymmetricKey());
}

void to_json(nlohmann::json& j, KeyPublishToDevice const& kp)
{
  j["recipient"] = kp.recipient();
  j["resourceId"] = kp.resourceId();
  j["key"] = kp.encryptedSymmetricKey();
}
}
}
}
