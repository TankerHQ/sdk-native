#include <Tanker/Encryptor/v4.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Streams/DecryptionStream.hpp>
#include <Tanker/Streams/EncryptionStreamV4.hpp>
#include <Tanker/Streams/Header.hpp>
#include <Tanker/Streams/Helpers.hpp>

#include <tconcurrent/coroutine.hpp>

using Tanker::Trustchain::ResourceId;

using namespace Tanker::Errors;
using namespace Tanker::Streams;

namespace Tanker
{
namespace
{
constexpr auto sizeOfChunkSize = sizeof(std::uint32_t);
constexpr auto versionSize = 1;
constexpr auto headerSize =
    versionSize + sizeOfChunkSize + ResourceId::arraySize;

// version 4 format layout:
// N * chunk of encryptedChunkSize:
// header: [version, 1B] [chunkSize, 4B] [ResourceId, 16B]
// content: [IV seed, 24B] [ciphertext, variable] [MAC, 16B]

constexpr std::uint32_t clearChunkSize(std::uint32_t encryptedChunkSize)
{
  return encryptedChunkSize - headerSize - Crypto::AeadIv::arraySize -
         Trustchain::ResourceId::arraySize;
}
}

std::uint64_t EncryptorV4::encryptedSize(std::uint64_t clearSize,
                                         std::uint32_t encryptedChunkSize)
{
  auto const chunkSize = clearChunkSize(encryptedChunkSize);
  auto const chunks = clearSize / chunkSize;
  auto const lastClearChunkSize = clearSize % chunkSize;
  return chunks * encryptedChunkSize + headerSize + Crypto::AeadIv::arraySize +
         Crypto::encryptedSize(lastClearChunkSize);
}

std::uint64_t EncryptorV4::decryptedSize(
    gsl::span<std::uint8_t const> encryptedData)
{
  Serialization::SerializedSource ss{encryptedData};
  auto const header = Serialization::deserialize<Header>(ss);

  // aead overhead
  if (ss.remaining_size() < Crypto::Mac::arraySize)
    throw formatEx(Errc::InvalidArgument, "truncated encrypted buffer");
  auto const chunks = encryptedData.size() / header.encryptedChunkSize();
  auto const lastEncryptedChunkSize =
      encryptedData.size() % header.encryptedChunkSize();
  if (lastEncryptedChunkSize < Crypto::AeadIv::arraySize + headerSize)
    throw formatEx(Errc::InvalidArgument, "truncated encrypted buffer");
  auto const lastClearChunkSize =
      lastEncryptedChunkSize - Crypto::AeadIv::arraySize - headerSize;
  return chunks * clearChunkSize(header.encryptedChunkSize()) +
         Crypto::decryptedSize(lastClearChunkSize);
}

tc::cotask<EncryptionMetadata> EncryptorV4::encrypt(
    gsl::span<std::uint8_t> encryptedData,
    gsl::span<std::uint8_t const> clearData,
    std::uint32_t encryptedChunkSize)
{
  TC_RETURN(TC_AWAIT(encrypt(encryptedData,
                             clearData,
                             Crypto::getRandom<Trustchain::ResourceId>(),
                             Crypto::makeSymmetricKey(),
                             encryptedChunkSize)));
}

tc::cotask<EncryptionMetadata> EncryptorV4::encrypt(
    gsl::span<std::uint8_t> encryptedData,
    gsl::span<std::uint8_t const> clearData,
    Trustchain::ResourceId const& resourceId,
    Crypto::SymmetricKey const& key,
    std::uint32_t encryptedChunkSize)
{
  EncryptionStreamV4 encryptor(
      bufferViewToInputSource(clearData), resourceId, key, encryptedChunkSize);

  while (auto const nbRead = TC_AWAIT(encryptor(encryptedData)))
    encryptedData = encryptedData.subspan(nbRead);

  TC_RETURN(
      (EncryptionMetadata{encryptor.resourceId(), encryptor.symmetricKey()}));
}

tc::cotask<std::uint64_t> EncryptorV4::decrypt(
    gsl::span<std::uint8_t> decryptedData,
    Crypto::SymmetricKey const& key,
    gsl::span<std::uint8_t const> encryptedData)
{
  auto const initialSize = decryptedData.size();

  auto decryptor = TC_AWAIT(DecryptionStream::create(
      bufferViewToInputSource(encryptedData),
      [&key](auto) -> tc::cotask<Crypto::SymmetricKey> { TC_RETURN(key); }));

  while (auto const nbRead = TC_AWAIT(decryptor(decryptedData)))
    decryptedData = decryptedData.subspan(nbRead);

  if (!decryptedData.empty())
    throw Errors::AssertionError(fmt::format(
        "EncryptorV4: got less than expected data (expected: {}, missing: {})",
        initialSize,
        decryptedData.size()));

  TC_RETURN(initialSize);
}

ResourceId EncryptorV4::extractResourceId(
    gsl::span<std::uint8_t const> encryptedData)
{
  Serialization::SerializedSource ss{encryptedData};
  return Serialization::deserialize<Header>(ss).resourceId();
}
}
