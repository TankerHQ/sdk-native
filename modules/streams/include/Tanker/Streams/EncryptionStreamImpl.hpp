#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Serialization/Serialization.hpp>

using namespace Tanker::Errors;

namespace Tanker
{
namespace Streams
{
template <typename Derived>
EncryptionStream<Derived>::EncryptionStream(
    InputSource cb,
    Trustchain::ResourceId const& resourceId,
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

template <typename Derived>
Trustchain::ResourceId const& EncryptionStream<Derived>::resourceId() const
{
  return _resourceId;
}

template <typename Derived>
Crypto::SymmetricKey const& EncryptionStream<Derived>::symmetricKey() const
{
  return _key;
}

template <typename Derived>
tc::cotask<void> EncryptionStream<Derived>::processInput()
{
  TC_AWAIT(static_cast<Derived*>(this)->encryptChunk());
}
}
}
