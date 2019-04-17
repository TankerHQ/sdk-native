#include <Tanker/Trustchain/Actions/DeviceCreation/v1.hpp>

#include <Tanker/Serialization/Serialization.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void from_serialized(Serialization::SerializedSource& ss, DeviceCreation1& dc)
{
  Serialization::deserialize_to(ss, dc._ephemeralPublicSignatureKey);
  Serialization::deserialize_to(ss, dc._userId);
  Serialization::deserialize_to(ss, dc._delegationSignature);
  Serialization::deserialize_to(ss, dc._publicSignatureKey);
  Serialization::deserialize_to(ss, dc._publicEncryptionKey);
}

std::uint8_t* to_serialized(std::uint8_t* it, DeviceCreation1 const& dc)
{
  it = Serialization::serialize(it, dc.ephemeralPublicSignatureKey());
  it = Serialization::serialize(it, dc.userId());
  it = Serialization::serialize(it, dc.delegationSignature());
  it = Serialization::serialize(it, dc.publicSignatureKey());
  return Serialization::serialize(it, dc.publicEncryptionKey());
}
}
}
}
