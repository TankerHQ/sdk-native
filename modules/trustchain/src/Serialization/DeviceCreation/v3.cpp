#include <Tanker/Trustchain/Actions/DeviceCreation/v3.hpp>

#include <Tanker/Serialization/Serialization.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void from_serialized(Serialization::SerializedSource& ss, DeviceCreation3& dc)
{
  Serialization::deserialize_to(ss, static_cast<DeviceCreation1&>(dc));
  Serialization::deserialize_to(ss, dc._publicUserEncryptionKey);
  Serialization::deserialize_to(ss, dc._sealedPrivateUserEncryptionKey);
  dc._isGhostDevice = static_cast<bool>(ss.read(1)[0]);
}

std::uint8_t* to_serialized(std::uint8_t* it, DeviceCreation3 const& dc)
{
  it = Serialization::serialize(it, static_cast<DeviceCreation1 const&>(dc));
  it = Serialization::serialize(it, dc.publicUserEncryptionKey());
  it = Serialization::serialize(it, dc.sealedPrivateUserEncryptionKey());
  *it++ = static_cast<std::uint8_t>(dc.isGhostDevice());
  return it;
}
}
}
}
