#include <Tanker/Streams/EncryptionStreamV4.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>

using namespace Tanker::Errors;

namespace Tanker::Streams
{
EncryptionStreamV4::EncryptionStreamV4(InputSource cb,
                                       std::uint32_t encryptedChunkSize)
  : EncryptionStreamV4(std::move(cb),
                       Crypto::getRandom<Crypto::SimpleResourceId>(),
                       Crypto::makeSymmetricKey(),
                       encryptedChunkSize)
{
}

EncryptionStreamV4::EncryptionStreamV4(
    InputSource cb,
    Crypto::SimpleResourceId const& resourceId,
    Crypto::SymmetricKey const& key,
    std::uint32_t encryptedChunkSize)
  : EncryptionStream(std::move(cb), resourceId, key, encryptedChunkSize)
{
}

tc::cotask<void> EncryptionStreamV4::encryptChunk()
{
  auto const clearInput =
      TC_AWAIT(readInputSource(_encryptedChunkSize - overhead));
  auto output = prepareWrite(Header::serializedSize +
                             Crypto::encryptedSize(clearInput.size()));

  Header const header(4u,
                      _encryptedChunkSize,
                      _resourceId,
                      Crypto::getRandom<Crypto::AeadIv>());
  Serialization::serialize(output.data(), header);
  auto const iv = Crypto::deriveIv(header.seed(), _chunkIndex);
  ++_chunkIndex;
  auto const cipherText = output.subspan(Header::serializedSize);
  Crypto::encryptAead(_key, iv, cipherText, clearInput, {});

  if (isInputEndOfStream())
    endOutputStream();
}
}
