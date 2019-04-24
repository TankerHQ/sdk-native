#include <Tanker/Trustchain/Actions/KeyPublishToUserGroup.hpp>

#include <Tanker/Serialization/Serialization.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void from_serialized(Serialization::SerializedSource& ss,
                     KeyPublishToUserGroup& kp)
{
  Serialization::deserialize_to(ss, kp._recipientPublicEncryptionKey);
  Serialization::deserialize_to(ss, kp._resourceId);
  Serialization::deserialize_to(ss, kp._sealedSymmetricKey);
}

std::uint8_t* to_serialized(std::uint8_t* it, KeyPublishToUserGroup const& kp)
{
  it = Serialization::serialize(it, kp.recipientPublicEncryptionKey());
  it = Serialization::serialize(it, kp.resourceId());
  return Serialization::serialize(it, kp.sealedSymmetricKey());
}
}
}
}
