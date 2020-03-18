#include <Tanker/Streams/DecryptionStream.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Streams/Header.hpp>

using namespace Tanker::Errors;

namespace Tanker
{
namespace Streams
{
namespace
{
void checkHeaderIntegrity(Header const& oldHeader, Header const& currentHeader)
{
  if (oldHeader.version() != currentHeader.version())
  {
    throw formatEx(Errc::DecryptionFailed,
                   "version mismatch in headers: expected {}, got {}",
                   oldHeader.version(),
                   currentHeader.version());
  }
  if (oldHeader.resourceId() != currentHeader.resourceId())
  {
    throw formatEx(Errc::DecryptionFailed,
                   "resourceId mismatch in headers: expected {}, got {}",
                   oldHeader.resourceId(),
                   currentHeader.resourceId());
  }
  if (oldHeader.encryptedChunkSize() != currentHeader.encryptedChunkSize())
  {
    throw formatEx(
        Errc::DecryptionFailed,
        "encryptedChunkSize mismatch in headers: expected {}, got {}",
        oldHeader.encryptedChunkSize(),
        currentHeader.encryptedChunkSize());
  }
}
}

DecryptionStream::DecryptionStream(InputSource cb)
  : BufferedStream(std::move(cb))
{
}

tc::cotask<DecryptionStream> DecryptionStream::create(InputSource cb,
                                                      ResourceKeyFinder finder)
{
  DecryptionStream decryptor(std::move(cb));

  TC_AWAIT(decryptor.readHeader());
  decryptor._key = TC_AWAIT(finder(decryptor._header.resourceId()));
  TC_AWAIT(decryptor.decryptChunk());
  TC_RETURN(std::move(decryptor));
}

tc::cotask<void> DecryptionStream::readHeader()
{
  auto const buffer = TC_AWAIT(readInputSource(Header::serializedSize));
  try
  {
    if (buffer.size() != Header::serializedSize)
    {
      throw Exception(make_error_code(Errc::IOError),
                      "could not read encrypted input header");
    }
    Serialization::deserialize_to(buffer, _header);
  }
  catch (Exception const& e)
  {
    if (e.errorCode() == Errc::InvalidArgument)
      throw Exception(make_error_code(Errc::DecryptionFailed), e.what());
    throw;
  }
}

Trustchain::ResourceId const& DecryptionStream::resourceId() const
{
  return _header.resourceId();
}

Crypto::SymmetricKey const& DecryptionStream::symmetricKey() const
{
  return _key;
}

tc::cotask<void> DecryptionStream::decryptChunk()
{
  auto const sizeToRead = _header.encryptedChunkSize() - Header::serializedSize;
  auto const encryptedInput = TC_AWAIT(readInputSource(sizeToRead));
  auto const iv = Crypto::deriveIv(_header.seed(), _chunkIndex);
  ++_chunkIndex;
  auto output = prepareWrite(Crypto::decryptedSize(encryptedInput.size()));
  Crypto::decryptAead(_key, iv.data(), output.data(), encryptedInput, {});
}

tc::cotask<void> DecryptionStream::processInput()
{
  auto const oldHeader = _header;
  TC_AWAIT(readHeader());
  checkHeaderIntegrity(oldHeader, _header);
  TC_AWAIT(decryptChunk());
}
}
}
