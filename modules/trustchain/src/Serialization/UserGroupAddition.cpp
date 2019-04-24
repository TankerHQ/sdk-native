#include <Tanker/Trustchain/Actions/UserGroupAddition.hpp>

#include <Tanker/Serialization/Serialization.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void from_serialized(Serialization::SerializedSource& ss,
                     UserGroupAddition& uga)
{
  Serialization::deserialize_to(ss, uga._groupId);
  Serialization::deserialize_to(ss, uga._previousGroupBlockHash);
  Serialization::deserialize_to(ss, uga._sealedPrivateEncryptionKeysForUsers);
  Serialization::deserialize_to(ss, uga._selfSignature);
}

std::uint8_t* to_serialized(std::uint8_t* it, UserGroupAddition const& uga)
{
  it = Serialization::serialize(it, uga.groupId());
  it = Serialization::serialize(it, uga.previousGroupBlockHash());
  it = Serialization::serialize(it, uga.sealedPrivateEncryptionKeysForUsers());
  return Serialization::serialize(it, uga.selfSignature());
}

std::size_t serialized_size(UserGroupAddition const& uga)
{
  return GroupId::arraySize + Crypto::Hash::arraySize +
         Serialization::serialized_size(
             uga.sealedPrivateEncryptionKeysForUsers()) +
         Crypto::Signature::arraySize;
}
}
}
}
