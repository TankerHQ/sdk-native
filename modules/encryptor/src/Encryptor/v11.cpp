#include <Tanker/Encryptor/v11.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Padding.hpp>
#include <Tanker/Crypto/SubkeySeed.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Streams/DecryptionStreamV11.hpp>
#include <Tanker/Streams/EncryptionStreamV11.hpp>
#include <Tanker/Streams/Helpers.hpp>
#include <Tanker/Streams/TransparentSessionHeader.hpp>

#include <sodium/randombytes.h>
#include <tconcurrent/coroutine.hpp>

using namespace Tanker::Errors;
using namespace Tanker::Streams;
using namespace Tanker::Crypto;

namespace Tanker
{
// version 11 format layout:
// header: [version, 1B] [session id, 16B] [resource id/seed, 16B]
// [chunk size, 4B]
// N * chunk of chunkSize:
// content: [padding size, 4B] [ciphertext, chunkSize-16] [MAC, 16B]

std::uint64_t EncryptorV11::encryptedSize(std::uint64_t clearSize,
                                          std::optional<std::uint32_t> paddingStep,
                                          std::uint32_t encryptedChunkSize)
{
  // -1 is because paddedFromClearSize assumes there is an extra 0x80,
  // however we use a separate padding size field instead of a marker byte
  auto const paddedSize = Padding::paddedFromClearSize(clearSize, paddingStep) - 1;
  auto const clearChunkSize = encryptedChunkSize - chunkOverhead;
  auto const chunks = paddedSize / clearChunkSize;
  auto const lastClearChunkSize = paddedSize % clearChunkSize;
  auto const lastEncryptedChunkSize = lastClearChunkSize + chunkOverhead;
  return headerSize + chunks * encryptedChunkSize + lastEncryptedChunkSize;
}

std::uint64_t EncryptorV11::decryptedSize(gsl::span<std::uint8_t const> encryptedData)
{
  Serialization::SerializedSource ss{encryptedData};
  auto const header = Serialization::deserialize<TransparentSessionHeader>(ss);

  // aead overhead
  if (ss.remaining_size() < chunkOverhead)
    throw formatEx(Errors::Errc::InvalidArgument, "truncated encrypted buffer");
  auto const chunks = ss.remaining_size() / header.encryptedChunkSize();
  auto const lastEncryptedChunkSize = ss.remaining_size() % header.encryptedChunkSize();
  if (lastEncryptedChunkSize < chunkOverhead)
    throw formatEx(Errors::Errc::InvalidArgument, "truncated encrypted buffer");
  auto const lastClearChunkSize = lastEncryptedChunkSize - chunkOverhead;
  return chunks * (header.encryptedChunkSize() - chunkOverhead) + lastClearChunkSize;
}

std::array<uint8_t, EncryptorV11::macDataSize> EncryptorV11::makeMacData(SimpleResourceId const& sessionId,
                                                                         SubkeySeed const& subkeySeed,
                                                                         std::uint32_t chunkSize)
{
  std::array<std::uint8_t, EncryptorV11::macDataSize> macData;
  macData[0] = EncryptorV11::version();
  std::copy(sessionId.begin(), sessionId.end(), macData.data() + versionSize);
  std::copy(subkeySeed.begin(), subkeySeed.end(), macData.data() + versionSize + SimpleResourceId::arraySize);
  std::copy((std::uint8_t*)&chunkSize,
            (std::uint8_t*)&chunkSize + sizeof(chunkSize),
            macData.data() + versionSize + SimpleResourceId::arraySize + SubkeySeed::arraySize);
  return macData;
}

SymmetricKey EncryptorV11::deriveSubkey(SymmetricKey const& sessionKey, SubkeySeed const& subkeySeed)
{
  auto constexpr bufLen = SymmetricKey::arraySize + SubkeySeed::arraySize;
  std::array<std::uint8_t, bufLen> hashBuf;
  std::copy(sessionKey.begin(), sessionKey.end(), hashBuf.data());
  std::copy(subkeySeed.begin(), subkeySeed.end(), hashBuf.data() + SymmetricKey::arraySize);
  return generichash<SymmetricKey>(gsl::make_span(hashBuf));
}

tc::cotask<EncryptCacheMetadata> EncryptorV11::encrypt(gsl::span<std::uint8_t> encryptedData,
                                                       gsl::span<std::uint8_t const> clearData,
                                                       Crypto::SimpleResourceId const& sessionId,
                                                       Crypto::SymmetricKey const& sessionKey,
                                                       std::optional<std::uint32_t> paddingStep,
                                                       std::uint32_t encryptedChunkSize)
{
  TC_RETURN(TC_AWAIT(encrypt(
      encryptedData, clearData, sessionId, sessionKey, getRandom<SubkeySeed>(), paddingStep, encryptedChunkSize)));
}

tc::cotask<EncryptCacheMetadata> EncryptorV11::encrypt(gsl::span<std::uint8_t> encryptedData,
                                                       gsl::span<std::uint8_t const> clearData,
                                                       Crypto::SimpleResourceId const& sessionId,
                                                       Crypto::SymmetricKey const& sessionKey,
                                                       Crypto::SubkeySeed const& subkeySeed,
                                                       std::optional<std::uint32_t> paddingStep,
                                                       std::uint32_t encryptedChunkSize)
{
  EncryptionStreamV11 encryptor(
      bufferViewToInputSource(clearData), sessionId, sessionKey, subkeySeed, paddingStep, encryptedChunkSize);

  while (auto const nbRead = TC_AWAIT(encryptor(encryptedData)))
    encryptedData = encryptedData.subspan(nbRead);

  TC_RETURN((EncryptCacheMetadata{encryptor.resourceId().sessionId(), encryptor.symmetricKey()}));
}

tc::cotask<std::uint64_t> EncryptorV11::decrypt(gsl::span<std::uint8_t> decryptedData,
                                                Encryptor::ResourceKeyFinder const& keyFinder,
                                                gsl::span<std::uint8_t const> encryptedData)
{
  auto const initialSize = decryptedData.size();

  auto decryptor = TC_AWAIT(DecryptionStreamV11::create(bufferViewToInputSource(encryptedData), keyFinder));

  while (auto const nbRead = TC_AWAIT(decryptor(decryptedData)))
    decryptedData = decryptedData.subspan(nbRead);

  // Remove padding
  TC_RETURN(initialSize - decryptedData.size());
}

CompositeResourceId EncryptorV11::extractResourceId(gsl::span<std::uint8_t const> encryptedData)
{
  Serialization::SerializedSource ss{encryptedData};
  return Serialization::deserialize<TransparentSessionHeader>(ss).resourceId();
}
}
