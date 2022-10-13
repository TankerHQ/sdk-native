#include <Tanker/Streams/EncryptionStreamV11.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Padding.hpp>
#include <Tanker/Serialization/Serialization.hpp>

using namespace Tanker::Errors;
using namespace Tanker::Crypto;

namespace Tanker::Streams
{
EncryptionStreamV11::EncryptionStreamV11(
    InputSource cb,
    Crypto::SimpleResourceId const& sessionId,
    Crypto::SymmetricKey const& sessionKey,
    std::optional<std::uint32_t> padding,
    std::uint32_t encryptedChunkSize)
  : EncryptionStreamV11(std::move(cb),
                        sessionId,
                        sessionKey,
                        getRandom<SubkeySeed>(),
                        padding,
                        encryptedChunkSize)
{
}

EncryptionStreamV11::EncryptionStreamV11(
    InputSource cb,
    Crypto::SimpleResourceId const& sessionId,
    Crypto::SymmetricKey const& sessionKey,
    Crypto::SubkeySeed const& subkeySeed,
    std::optional<std::uint32_t> padding,
    std::uint32_t encryptedChunkSize)
  : EncryptionStream(std::move(cb),
                     CompositeResourceId::newTransparentSessionId(
                         sessionId, SimpleResourceId{subkeySeed}),
                     sessionKey,
                     encryptedChunkSize),
    _associatedData(
        EncryptorV11::makeMacData(sessionId, subkeySeed, encryptedChunkSize)),
    _subkey(EncryptorV11::deriveSubkey(sessionKey, subkeySeed)),
    _paddingStep(padding),
    _paddingLeftToAdd(std::nullopt),
    _wroteHeader(false)
{
}

tc::cotask<void> EncryptionStreamV11::writeHeader()
{
  auto output = prepareWrite(TransparentSessionHeader::serializedSize);
  TransparentSessionHeader const header(11u, _encryptedChunkSize, _resourceId);
  Serialization::serialize(output.data(), header);

  _wroteHeader = true;
}

tc::cotask<void> EncryptionStreamV11::encryptChunk()
{
  if (!_wroteHeader)
    return writeHeader();

  auto clearChunkSize = _encryptedChunkSize - overhead;
  std::vector<uint8_t> paddedInputBuf;
  auto paddingSize = 0;

  if (_paddingLeftToAdd)
  {
    // This is a padding only block, write remaining padding bytes
    paddingSize = std::min<std::int64_t>(clearChunkSize, *_paddingLeftToAdd);
    paddedInputBuf =
        std::vector<uint8_t>(EncryptorV11::paddingSizeSize + paddingSize, 0);
    _paddingLeftToAdd = *_paddingLeftToAdd - paddingSize;
  }
  else
  {
    auto const clearData = TC_AWAIT(readInputSource(clearChunkSize));
    // If we reached the end of input
    if (clearData.size() < clearChunkSize)
    {
      auto const totalClearSize =
          _chunkIndex * clearChunkSize + clearData.size();
      _paddingLeftToAdd =
          Padding::paddedFromClearSize(totalClearSize, _paddingStep) -
          totalClearSize - 1;
      paddingSize = std::min<std::int64_t>(clearChunkSize - clearData.size(),
                                           *_paddingLeftToAdd);
      _paddingLeftToAdd = *_paddingLeftToAdd - paddingSize;
    }

    paddedInputBuf.resize(EncryptorV11::paddingSizeSize + paddingSize +
                          clearData.size());
    std::copy(
        clearData.begin(),
        clearData.end(),
        paddedInputBuf.begin() + EncryptorV11::paddingSizeSize + paddingSize);
  }
  Serialization::serialize<uint32_t>(paddedInputBuf.data(), paddingSize);

  auto output = prepareWrite(encryptedSize(paddedInputBuf.size()));
  auto const sessId = _resourceId.sessionId();
  AeadIv seedIv{};
  std::copy(sessId.begin(), sessId.end(), seedIv.begin());
  auto const iv = Crypto::deriveIv(seedIv, _chunkIndex);
  ++_chunkIndex;
  Crypto::encryptAead(_subkey, iv, output, paddedInputBuf, _associatedData);

  if (_paddingLeftToAdd && *_paddingLeftToAdd == 0 &&
      paddedInputBuf.size() < _encryptedChunkSize - Mac::arraySize)
    endOutputStream();
}
}
