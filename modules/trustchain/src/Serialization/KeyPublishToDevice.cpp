#include <Tanker/Trustchain/Actions/KeyPublishToDevice.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <stdexcept>
#include <string>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void from_serialized(Serialization::SerializedSource& ss,
                     KeyPublishToDevice& kp)
{
  Serialization::deserialize_to(ss, kp._recipient);
  Serialization::deserialize_to(ss, kp._mac);
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
  it = Serialization::serialize(it, kp.mac());
  it = Serialization::varint_write(it, Crypto::EncryptedSymmetricKey::arraySize);
  return Serialization::serialize(it, kp.encryptedSymmetricKey());
}
}
}
}
