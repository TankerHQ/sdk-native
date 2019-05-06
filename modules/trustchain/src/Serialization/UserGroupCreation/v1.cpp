#include <Tanker/Trustchain/Actions/UserGroupCreation/v1.hpp>

#include <Tanker/Serialization/Serialization.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void from_serialized(Serialization::SerializedSource& ss,
                     UserGroupCreation1& ugc)
{
  Serialization::deserialize_to(ss, ugc._publicSignatureKey);
  Serialization::deserialize_to(ss, ugc._publicEncryptionKey);
  Serialization::deserialize_to(ss, ugc._sealedPrivateSignatureKey);
  Serialization::deserialize_to(ss, ugc._sealedPrivateEncryptionKeysForUsers);
  Serialization::deserialize_to(ss, ugc._selfSignature);
}

std::uint8_t* to_serialized(std::uint8_t* it, UserGroupCreation1 const& ugc)
{
  it = Serialization::serialize(it, ugc.publicSignatureKey());
  it = Serialization::serialize(it, ugc.publicEncryptionKey());
  it = Serialization::serialize(it, ugc.sealedPrivateSignatureKey());
  it = Serialization::serialize(it, ugc.sealedPrivateEncryptionKeysForUsers());
  return Serialization::serialize(it, ugc.selfSignature());
}

std::size_t serialized_size(UserGroupCreation1 const& ugc)
{
  return Crypto::PublicSignatureKey::arraySize +
         Crypto::PublicEncryptionKey::arraySize +
         Crypto::SealedPrivateSignatureKey::arraySize +
         Serialization::serialized_size(
             ugc.sealedPrivateEncryptionKeysForUsers()) +
         Crypto::Signature::arraySize;
}
}
}
}
