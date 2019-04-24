#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>

#include <Tanker/Serialization/Serialization.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void from_serialized(Serialization::SerializedSource& ss,
                     ProvisionalIdentityClaim& pic)
{
  Serialization::deserialize_to(ss, pic._userId);
  Serialization::deserialize_to(ss, pic._appSignaturePublicKey);
  Serialization::deserialize_to(ss, pic._tankerSignaturePublicKey);
  Serialization::deserialize_to(ss, pic._authorSignatureByAppKey);
  Serialization::deserialize_to(ss, pic._authorSignatureByTankerKey);
  Serialization::deserialize_to(ss, pic._userPublicEncryptionKey);
  Serialization::deserialize_to(ss, pic._sealedPrivateEncryptionKeys);
}

std::uint8_t* to_serialized(std::uint8_t* it,
                            ProvisionalIdentityClaim const& pic)
{
  it = Serialization::serialize(it, pic.userId());
  it = Serialization::serialize(it, pic.appSignaturePublicKey());
  it = Serialization::serialize(it, pic.tankerSignaturePublicKey());
  it = Serialization::serialize(it, pic.authorSignatureByAppKey());
  it = Serialization::serialize(it, pic.authorSignatureByTankerKey());
  it = Serialization::serialize(it, pic.userPublicEncryptionKey());
  it = Serialization::serialize(it, pic.sealedPrivateEncryptionKeys());
  return it;
}
}
}
}
