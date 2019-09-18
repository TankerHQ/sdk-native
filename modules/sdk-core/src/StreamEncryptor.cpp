#include <Tanker/StreamEncryptor.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Streams/Header.hpp>

#include <algorithm>

using namespace Tanker::Errors;

namespace Tanker
{
namespace
{
constexpr std::uint32_t clearChunkSize(std::uint32_t encryptedChunkSize)
{
  return encryptedChunkSize - Streams::Header::serializedSize -
         Crypto::Mac::arraySize;
}
}

StreamEncryptor::StreamEncryptor(Streams::InputSource cb)
  : StreamEncryptor(std::move(cb), Streams::Header::defaultEncryptedChunkSize)
{
}

StreamEncryptor::StreamEncryptor(Streams::InputSource cb,
                                 std::uint32_t encryptedChunkSize)
  : BufferedStream(std::move(cb)), _encryptedChunkSize(encryptedChunkSize)
{
  if (encryptedChunkSize <
      Streams::Header::serializedSize + Crypto::Mac::arraySize)
  {
    throw AssertionError("invalid encrypted chunk size");
  }
  Crypto::randomFill(_resourceId);
  _key = Crypto::makeSymmetricKey();
}

Trustchain::ResourceId const& StreamEncryptor::resourceId() const
{
  return _resourceId;
}

Crypto::SymmetricKey const& StreamEncryptor::symmetricKey() const
{
  return _key;
}

tc::cotask<void> StreamEncryptor::encryptChunk()
{
  auto const clearInput =
      TC_AWAIT(readInputSource(clearChunkSize(_encryptedChunkSize)));
  auto output = prepareWrite(Streams::Header::serializedSize +
                             Crypto::encryptedSize(clearInput.size()));

  Streams::Header const header(
      _encryptedChunkSize, _resourceId, Crypto::getRandom<Crypto::AeadIv>());
  auto const it = Serialization::serialize(output.data(), header);
  auto const iv = Crypto::deriveIv(header.seed(), _chunkIndex);
  ++_chunkIndex;
  Crypto::encryptAead(_key, iv.data(), it, clearInput, {});
}

tc::cotask<void> StreamEncryptor::processInput()
{
  TC_AWAIT(encryptChunk());
}
}
