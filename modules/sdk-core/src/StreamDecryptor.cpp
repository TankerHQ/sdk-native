#include <Tanker/StreamDecryptor.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/StreamHeader.hpp>

#include <algorithm>

using namespace Tanker::Errors;

namespace Tanker
{
namespace
{
void checkHeaderIntegrity(StreamHeader const& oldHeader,
                          StreamHeader const& currentHeader)
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

StreamDecryptor::StreamDecryptor(StreamInputSource cb)
  : BufferedStream(std::move(cb))
{
}

tc::cotask<StreamDecryptor> StreamDecryptor::create(StreamInputSource cb,
                                                    ResourceKeyFinder finder)
{
  StreamDecryptor decryptor(std::move(cb));

  TC_AWAIT(decryptor.readHeader());
  decryptor._key = TC_AWAIT(finder(decryptor._header.resourceId()));
  TC_AWAIT(decryptor.decryptChunk());
  TC_RETURN(std::move(decryptor));
}

tc::cotask<void> StreamDecryptor::readHeader()
{
  auto const buffer = TC_AWAIT(readInputSource(StreamHeader::serializedSize));
  try
  {
    if (buffer.size() != StreamHeader::serializedSize)
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

Trustchain::ResourceId const& StreamDecryptor::resourceId() const
{
  return _header.resourceId();
}

Crypto::SymmetricKey const& StreamDecryptor::symmetricKey() const
{
  return _key;
}

tc::cotask<void> StreamDecryptor::decryptChunk()
{
  auto const sizeToRead =
      _header.encryptedChunkSize() - StreamHeader::serializedSize;
  auto const encryptedInput = TC_AWAIT(readInputSource(sizeToRead));
  auto const iv = Crypto::deriveIv(_header.seed(), _chunkIndex);
  ++_chunkIndex;
  auto output = prepareWrite(Crypto::decryptedSize(encryptedInput.size()));
  Crypto::decryptAead(_key, iv.data(), output.data(), encryptedInput, {});
}

tc::cotask<void> StreamDecryptor::processInput()
{
  auto const oldHeader = _header;
  TC_AWAIT(readHeader());
  checkHeaderIntegrity(oldHeader, _header);
  TC_AWAIT(decryptChunk());
}
}
