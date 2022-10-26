#include <Tanker/Streams/DecryptionStreamV8.hpp>

#include <Tanker/Crypto/Padding.hpp>
#include <Tanker/Errors/Exception.hpp>

namespace Tanker::Streams
{
DecryptionStreamV8::DecryptionStreamV8(InputSource cb,
                                       Header header,
                                       Crypto::SymmetricKey key)
  : DecryptionStream(std::move(cb), header, key)
{
}

tc::cotask<void> DecryptionStreamV8::decryptChunk()
{
  // There's an additional copy the header for each chunk in this format
  if (_chunkIndex > 0)
  {
    auto const newHeader = TC_AWAIT(readHeader());
    checkHeaderIntegrity(_header, newHeader);
    _header = newHeader;
  }

  auto const sizeToRead = _header.encryptedChunkSize() - Header::serializedSize;
  auto const encryptedInput = TC_AWAIT(readInputSource(sizeToRead));
  auto const iv = Crypto::deriveIv(_header.seed(), _chunkIndex);
  ++_chunkIndex;
  auto output = prepareWrite(Crypto::decryptedSize(encryptedInput.size()));

  std::vector<uint8_t> associatedData(Header::serializedSize);
  to_serialized(associatedData.data(), _header);

  Crypto::decryptAead(_key, iv, output, encryptedInput, associatedData);

  auto const unpaddedSize = Padding::unpaddedSize(output);
  if (_onlyPaddingLeft)
  {
    if (unpaddedSize != 0)
      throw Errors::formatEx(Errors::Errc::DecryptionFailed,
                             "unable to remove padding");
  }
  else
  {
    if (unpaddedSize < output.size() - 1)
      _onlyPaddingLeft = true;
  }

  shrinkOutput(unpaddedSize);

  if (isInputEndOfStream())
    endOutputStream();
}

tc::cotask<std::optional<Crypto::SymmetricKey>> DecryptionStreamV8::tryGetKey(
    ResourceKeyFinder const& finder, Header const& header)
{
  TC_RETURN(TC_AWAIT(finder(header.resourceId())));
}
}
