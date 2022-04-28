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
}

template <typename Derived>
DecryptionStream<Derived>::DecryptionStream(InputSource cb)
  : BufferedStream<Derived>(std::move(cb))
{
}

template <typename Derived>
tc::cotask<Derived> DecryptionStream<Derived>::create(InputSource cb,
                                                      ResourceKeyFinder finder)
{
  Derived decryptor(std::move(cb));

  TC_AWAIT(decryptor.readHeader());
  decryptor._key = TC_AWAIT(finder(decryptor._header.resourceId()));
  TC_AWAIT(decryptor.decryptChunk());
  TC_RETURN(std::move(decryptor));
}

template <typename Derived>
tc::cotask<void> DecryptionStream<Derived>::readHeader()
{
  auto const buffer = TC_AWAIT(this->readInputSource(Header::serializedSize));
  try
  {
    if (buffer.size() != Header::serializedSize)
    {
      throw Exception(
          make_error_code(Errc::DecryptionFailed),
          "truncated buffer: could not read encrypted input header");
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

template <typename Derived>
Trustchain::ResourceId const& DecryptionStream<Derived>::resourceId() const
{
  return _header.resourceId();
}

template <typename Derived>
Crypto::SymmetricKey const& DecryptionStream<Derived>::symmetricKey() const
{
  return _key;
}

template <typename Derived>
tc::cotask<void> DecryptionStream<Derived>::processInput()
{
  auto const oldHeader = _header;
  TC_AWAIT(readHeader());
  checkHeaderIntegrity(oldHeader, _header);
  TC_AWAIT(static_cast<Derived*>(this)->decryptChunk());
}

template <typename Derived>
void DecryptionStream<Derived>::checkHeaderIntegrity(
    Header const& oldHeader, Header const& currentHeader)
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
}
