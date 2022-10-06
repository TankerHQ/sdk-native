#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Serialization/Serialization.hpp>

using namespace Tanker::Errors;

namespace Tanker
{
namespace Streams
{
template <typename Derived, typename ResourceIdType>
EncryptionStream<Derived, ResourceIdType>::EncryptionStream(
    InputSource cb,
    ResourceIdType const& resourceId,
    Crypto::SymmetricKey const& key,
    std::uint32_t encryptedChunkSize)
  : BufferedStream<Derived>(std::move(cb)),
    _encryptedChunkSize(encryptedChunkSize),
    _resourceId{resourceId},
    _key{key}
{
  if (encryptedChunkSize < Header::serializedSize + Crypto::Mac::arraySize)
    throw AssertionError("invalid encrypted chunk size");
}

template <typename Derived, typename ResourceIdType>
ResourceIdType const& EncryptionStream<Derived, ResourceIdType>::resourceId()
    const
{
  return _resourceId;
}

template <typename Derived, typename ResourceIdType>
Crypto::SymmetricKey const&
EncryptionStream<Derived, ResourceIdType>::symmetricKey() const
{
  return _key;
}

template <typename Derived, typename ResourceIdType>
tc::cotask<void> EncryptionStream<Derived, ResourceIdType>::processInput()
{
  TC_AWAIT(static_cast<Derived*>(this)->encryptChunk());
}
}
}
