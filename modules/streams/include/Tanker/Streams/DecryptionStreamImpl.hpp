#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Streams/Header.hpp>

using namespace Tanker::Errors;

namespace Tanker::Streams
{
namespace
{
template <typename HeaderType>
void deserializeHeaderTo(gsl::span<std::uint8_t const> buffer,
                         HeaderType& output)
try
{
  if (buffer.size() != HeaderType::serializedSize)
  {
    throw Exception(make_error_code(Errc::DecryptionFailed),
                    "truncated buffer: could not read encrypted input header");
  }
  Serialization::deserialize_to(buffer, output);
}
catch (Exception const& e)
{
  if (e.errorCode() == Errc::InvalidArgument)
    throw Exception(make_error_code(Errc::DecryptionFailed), e.what());
  throw;
}
}

template <typename Derived>
DecryptionStream<Derived>::DecryptionStream(InputSource cb,
                                            Header header,
                                            Crypto::SymmetricKey key)
  : BufferedStream<Derived>(std::move(cb)), _key(key), _header(header)
{
}

template <typename Derived>
tc::cotask<Derived> DecryptionStream<Derived>::create(
    InputSource cb, ResourceKeyFinder const& finder)
{
  std::array<uint8_t, Header::serializedSize> headerBuf;
  Header header;
  if (TC_AWAIT(readStream(headerBuf, cb)) < Header::serializedSize)
    throw Exception(make_error_code(Errc::DecryptionFailed),
                    "truncated buffer: could not read encrypted input header");
  deserializeHeaderTo(headerBuf, header);

  std::optional key = TC_AWAIT(Derived::tryGetKey(finder, header));
  if (!key)
    throw formatEx(Errors::Errc::InvalidArgument,
                   "key not found for resource: {:s}",
                   header.resourceId());

  Derived decryptor(std::move(cb), header, *key);
  TC_AWAIT(decryptor.decryptChunk());
  TC_RETURN(std::move(decryptor));
}

template <typename Derived>
tc::cotask<void> DecryptionStream<Derived>::readHeader()
{
  auto const buffer = TC_AWAIT(this->readInputSource(Header::serializedSize));
  deserializeHeaderTo(buffer, _header);
}

template <typename Derived>
Crypto::SimpleResourceId const& DecryptionStream<Derived>::resourceId() const
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
