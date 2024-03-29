#include <Tanker/Streams/DecryptionStreamV4.hpp>

namespace Tanker::Streams
{
DecryptionStreamV4::DecryptionStreamV4(InputSource cb, Header header, Crypto::SymmetricKey key)
  : DecryptionStream(std::move(cb), header, key)
{
}

tc::cotask<void> DecryptionStreamV4::decryptChunk()
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
  Crypto::decryptAead(_key, iv, output, encryptedInput, {});

  if (isInputEndOfStream())
    endOutputStream();
}

tc::cotask<std::optional<Crypto::SymmetricKey>> DecryptionStreamV4::tryGetKey(ResourceKeyFinder const& finder,
                                                                              Header const& header)
{
  TC_RETURN(TC_AWAIT(finder(header.resourceId())));
}
}
