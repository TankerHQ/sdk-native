#include <Tanker/Encryptor/v8.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Padding.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Streams/DecryptionStreamV8.hpp>
#include <Tanker/Streams/EncryptionStreamV8.hpp>
#include <Tanker/Streams/Header.hpp>
#include <Tanker/Streams/Helpers.hpp>

#include <tconcurrent/coroutine.hpp>

using Tanker::Crypto::SimpleResourceId;

using namespace Tanker::Errors;
using namespace Tanker::Streams;

namespace Tanker
{
namespace
{
constexpr auto sizeOfChunkSize = sizeof(std::uint32_t);
constexpr auto versionSize = 1;
constexpr auto headerSize = versionSize + sizeOfChunkSize +
                            SimpleResourceId::arraySize +
                            Crypto::AeadIv::arraySize;
constexpr auto chunkOverhead = headerSize + Crypto::Mac::arraySize + 1;

// version 8 format layout:
// N * chunk of encryptedChunkSize:
// header: [version, 1B] [chunkSize, 4B] [ResourceId, 16B] [IV seed, 24B]
// content: [ciphertext, variable] [MAC, 16B]
}

std::uint64_t EncryptorV8::encryptedSize(
    std::uint64_t clearSize,
    std::optional<std::uint32_t> paddingStep,
    std::uint32_t encryptedChunkSize)
{
  auto const paddedSize =
      Padding::paddedFromClearSize(clearSize, paddingStep) - 1;
  auto const chunkSize = encryptedChunkSize - chunkOverhead;
  auto const chunks = paddedSize / chunkSize;
  auto const lastClearChunkSize = paddedSize % chunkSize;
  auto const lastEncryptedChunkSize = lastClearChunkSize + chunkOverhead;
  return chunks * encryptedChunkSize + lastEncryptedChunkSize;
}

std::uint64_t EncryptorV8::decryptedSize(
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
  if (lastEncryptedChunkSize < chunkOverhead)
    throw formatEx(Errc::InvalidArgument, "truncated encrypted buffer");
  auto const lastClearChunkSize = lastEncryptedChunkSize - chunkOverhead;
  return chunks * (header.encryptedChunkSize() - chunkOverhead) +
         lastClearChunkSize;
}

tc::cotask<EncryptionMetadata> EncryptorV8::encrypt(
    gsl::span<std::uint8_t> encryptedData,
    gsl::span<std::uint8_t const> clearData,
    std::optional<std::uint32_t> paddingStep,
    std::uint32_t encryptedChunkSize)
{
  TC_RETURN(TC_AWAIT(encrypt(encryptedData,
                             clearData,
                             Crypto::getRandom<SimpleResourceId>(),
                             Crypto::makeSymmetricKey(),
                             paddingStep,
                             encryptedChunkSize)));
}

tc::cotask<EncryptionMetadata> EncryptorV8::encrypt(
    gsl::span<std::uint8_t> encryptedData,
    gsl::span<std::uint8_t const> clearData,
    Crypto::SimpleResourceId const& resourceId,
    Crypto::SymmetricKey const& key,
    std::optional<std::uint32_t> paddingStep,
    std::uint32_t encryptedChunkSize)
{
  EncryptionStreamV8 encryptor(bufferViewToInputSource(clearData),
                               resourceId,
                               key,
                               paddingStep,
                               encryptedChunkSize);

  while (auto const nbRead = TC_AWAIT(encryptor(encryptedData)))
    encryptedData = encryptedData.subspan(nbRead);

  TC_RETURN(
      (EncryptionMetadata{encryptor.resourceId(), encryptor.symmetricKey()}));
}

tc::cotask<std::uint64_t> EncryptorV8::decrypt(
    gsl::span<std::uint8_t> decryptedData,
    Encryptor::ResourceKeyFinder const& keyFinder,
    gsl::span<std::uint8_t const> encryptedData)
{
  auto const initialSize = decryptedData.size();
  auto decryptor = TC_AWAIT(DecryptionStreamV8::create(
      bufferViewToInputSource(encryptedData), keyFinder));

  while (auto const nbRead = TC_AWAIT(decryptor(decryptedData)))
    decryptedData = decryptedData.subspan(nbRead);

  // Remove padding
  TC_RETURN(initialSize - decryptedData.size());
}

SimpleResourceId EncryptorV8::extractResourceId(
    gsl::span<std::uint8_t const> encryptedData)
{
  Serialization::SerializedSource ss{encryptedData};
  return Serialization::deserialize<Header>(ss).resourceId();
}
}
