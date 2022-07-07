#include <Tanker/Streams/EncryptionStreamV8.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Padding.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <gsl/gsl-lite.hpp>

using namespace Tanker::Errors;

namespace Tanker::Streams
{
EncryptionStreamV8::EncryptionStreamV8(InputSource cb,
                                       std::optional<std::uint32_t> padding,
                                       std::uint32_t encryptedChunkSize)
  : EncryptionStreamV8(std::move(cb),
                       Crypto::getRandom<Trustchain::ResourceId>(),
                       Crypto::makeSymmetricKey(),
                       padding,
                       encryptedChunkSize)
{
}

EncryptionStreamV8::EncryptionStreamV8(InputSource cb,
                                       Trustchain::ResourceId const& resourceId,
                                       Crypto::SymmetricKey const& key,
                                       std::optional<std::uint32_t> padding,
                                       std::uint32_t encryptedChunkSize)
  : EncryptionStream(cb, resourceId, key, encryptedChunkSize),
    _paddingStep(padding)
{
}

tc::cotask<void> EncryptionStreamV8::encryptChunk()
{
  auto currentClearChunkSize = _encryptedChunkSize - overhead;
  std::vector<std::uint8_t> clearInput;
  if (!_paddingLeftToAdd)
  {
    auto const span = TC_AWAIT(readInputSource(currentClearChunkSize));
    clearInput = std::vector(span.begin(), span.end());
    // If we reached the end of input
    if (clearInput.size() < currentClearChunkSize)
    {
      auto const totalClearSize =
          _chunkIndex * currentClearChunkSize + clearInput.size();
      _paddingLeftToAdd =
          Padding::paddedFromClearSize(totalClearSize, _paddingStep) - 1 -
          totalClearSize;
    }
  }
  clearInput.push_back(0x80);
  if (_paddingLeftToAdd && clearInput.size() - 1 < currentClearChunkSize)
  {
    auto const paddingForCurrentChunk = std::min<std::int64_t>(
        currentClearChunkSize - (clearInput.size() - 1), *_paddingLeftToAdd);
    clearInput.resize(clearInput.size() + paddingForCurrentChunk, 0x00);
    *_paddingLeftToAdd -= paddingForCurrentChunk;
    if (*_paddingLeftToAdd == 0 &&
        clearInput.size() - 1 < currentClearChunkSize)
      endOutputStream();
  }

  auto output = prepareWrite(Header::serializedSize +
                             Crypto::encryptedSize(clearInput.size()));

  Header const header(8u,
                      _encryptedChunkSize,
                      _resourceId,
                      Crypto::getRandom<Crypto::AeadIv>());
  Serialization::serialize(output.data(), header);
  auto const associatedData = output.subspan(0, Header::serializedSize);
  auto const iv = Crypto::deriveIv(header.seed(), _chunkIndex);
  ++_chunkIndex;
  auto const cipherText = output.subspan(Header::serializedSize);
  Crypto::encryptAead(_key, iv, cipherText, clearInput, associatedData);
}
}
