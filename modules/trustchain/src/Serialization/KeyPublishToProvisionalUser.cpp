#include <Tanker/Trustchain/Actions/KeyPublishToProvisionalUser.hpp>

#include <Tanker/Serialization/Serialization.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void from_serialized(Serialization::SerializedSource& ss,
                     KeyPublishToProvisionalUser& kp)
{
  Serialization::deserialize_to(ss, kp._appPublicSignatureKey);
  Serialization::deserialize_to(ss, kp._tankerPublicSignatureKey);
  Serialization::deserialize_to(ss, kp._resourceId);
  Serialization::deserialize_to(ss, kp._twoTimesSealedSymmetricKey);
}

std::uint8_t* to_serialized(std::uint8_t* it,
                            KeyPublishToProvisionalUser const& kp)
{
  it = Serialization::serialize(it, kp.appPublicSignatureKey());
  it = Serialization::serialize(it, kp.tankerPublicSignatureKey());
  it = Serialization::serialize(it, kp.resourceId());
  return Serialization::serialize(it, kp.twoTimesSealedSymmetricKey());
}
}
}
}
