#include <Tanker/Trustchain/Actions/DeviceRevocation/v2.hpp>

#include <Tanker/Serialization/Serialization.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
std::size_t serialized_size(DeviceRevocation2 const& dr)
{
  return Trustchain::DeviceId::arraySize +
         (Crypto::PublicEncryptionKey::arraySize * 2) +
         Crypto::SealedPrivateEncryptionKey::arraySize +
         Serialization::serialized_size(dr.sealedUserKeysForDevices());
}

std::uint8_t* to_serialized(std::uint8_t* it, DeviceRevocation2 const& dr)
{
  it = Serialization::serialize(it, dr.deviceId());
  it = Serialization::serialize(it, dr.publicEncryptionKey());
  it = Serialization::serialize(it, dr.previousPublicEncryptionKey());
  it = Serialization::serialize(it, dr.sealedKeyForPreviousUserKey());
  return Serialization::serialize(it, dr.sealedUserKeysForDevices());
}


void from_serialized(Serialization::SerializedSource& ss, DeviceRevocation2& dr)
{
  Serialization::deserialize_to(ss, dr._deviceId);
  Serialization::deserialize_to(ss, dr._publicEncryptionKey);
  Serialization::deserialize_to(ss, dr._previousPublicEncryptionKey);
  Serialization::deserialize_to(ss, dr._sealedKeyForPreviousUserKey);
  Serialization::deserialize_to(ss, dr._sealedUserKeysForDevices);
}
}
}
}
