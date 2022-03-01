#include <Tanker/Streams/EncryptionStream.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Serialization/Serialization.hpp>

using namespace Tanker::Errors;

namespace Tanker
{
namespace Streams
{
namespace
{
constexpr std::uint32_t clearChunkSize(std::uint32_t encryptedChunkSize)
{
  return encryptedChunkSize - Header::serializedSize - Crypto::Mac::arraySize;
}
}

EncryptionStream::EncryptionStream(InputSource cb,
                                   std::uint32_t encryptedChunkSize)
  : EncryptionStream(std::move(cb),
                     Crypto::getRandom<Trustchain::ResourceId>(),
                     Crypto::makeSymmetricKey(),
                     encryptedChunkSize)
{
}

EncryptionStream::EncryptionStream(InputSource cb,
                                   Trustchain::ResourceId const& resourceId,
                                   Crypto::SymmetricKey const& key,
                                   std::uint32_t encryptedChunkSize)
  : BufferedStream(std::move(cb)),
    _encryptedChunkSize(encryptedChunkSize),
    _resourceId{resourceId},
    _key{key}
{
  if (encryptedChunkSize < Header::serializedSize + Crypto::Mac::arraySize)
    throw AssertionError("invalid encrypted chunk size");
}

Trustchain::ResourceId const& EncryptionStream::resourceId() const
{
  return _resourceId;
}

Crypto::SymmetricKey const& EncryptionStream::symmetricKey() const
{
  return _key;
}

tc::cotask<void> EncryptionStream::encryptChunk()
{
  auto const clearInput =
      TC_AWAIT(readInputSource(clearChunkSize(_encryptedChunkSize)));
  auto output = prepareWrite(Header::serializedSize +
                             Crypto::encryptedSize(clearInput.size()));

  Header const header(
      _encryptedChunkSize, _resourceId, Crypto::getRandom<Crypto::AeadIv>());
  Serialization::serialize(output.data(), header);
  auto const iv = Crypto::deriveIv(header.seed(), _chunkIndex);
  ++_chunkIndex;
  auto const cipherText = output.subspan(Header::serializedSize);
  Crypto::encryptAead(_key, iv, cipherText, clearInput, {});

  if (isInputEndOfStream())
    endOutputStream();
}

tc::cotask<void> EncryptionStream::processInput()
{
  TC_AWAIT(encryptChunk());
}
}
}
