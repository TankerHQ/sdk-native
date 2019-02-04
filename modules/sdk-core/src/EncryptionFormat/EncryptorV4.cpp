#include <Tanker/EncryptionFormat/EncryptorV4.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Serialization/Varint.hpp>

#include <algorithm>

namespace Tanker
{
namespace EncryptionFormat
{
namespace EncryptorV4
{
namespace
{
auto const versionSize = Serialization::varint_size(version());
constexpr auto encryptedChunkSize = 1024lu * 1024lu;
auto const clearChunkSize =
    Crypto::decryptedSize(encryptedChunkSize - Crypto::AeadIv::arraySize);
auto const sizeOfEncryptedChunkSize =
    Serialization::varint_size(encryptedChunkSize);

// version 4 format layout:
// [version, 1B] [RESOURCEID, 16B] +
// N * [[IV, 24B] [[ciphertext, variable] [MAC, 16B]]]
void checkEncryptedFormat(gsl::span<uint8_t const> encryptedData)
{
  auto const dataVersionResult = Serialization::varint_read(encryptedData);
  auto const chunkSizeResult =
      Serialization::varint_read(dataVersionResult.second);
  auto const overheadSize = ResourceId::arraySize + Crypto::AeadIv::arraySize +
                            Crypto::Mac::arraySize;
  assert(dataVersionResult.first == version());

  if (chunkSizeResult.second.size() < overheadSize)
    throw Error::DecryptFailed("truncated encrypted buffer");
}
}

uint64_t encryptedSize(uint64_t clearSize)
{
  auto const chunks = clearSize / clearChunkSize;
  auto const lastclearChunkSize = clearSize % clearChunkSize;
  auto const headerSize =
      versionSize + ResourceId::arraySize + sizeOfEncryptedChunkSize;
  return headerSize + chunks * encryptedChunkSize +
         Crypto::encryptedSize(lastclearChunkSize) + Crypto::AeadIv::arraySize;
}

uint64_t decryptedSize(gsl::span<uint8_t const> encryptedData)
{
  try
  {
    checkEncryptedFormat(encryptedData);

    auto const versionResult = Serialization::varint_read(encryptedData);
    auto const chunkSizeResult =
        Serialization::varint_read(versionResult.second);
    if (chunkSizeResult.second.size() < ResourceId::arraySize)
      throw Error::DecryptFailed("truncated encrypted buffer");
    auto const encryptedDataSize =
        chunkSizeResult.second.size() - ResourceId::arraySize;
    auto const chunks = encryptedDataSize / chunkSizeResult.first;
    auto const lastclearChunkSize =
        (encryptedDataSize % chunkSizeResult.first) - Crypto::AeadIv::arraySize;
    return chunks * clearChunkSize + Crypto::decryptedSize(lastclearChunkSize);
  }
  catch (std::out_of_range const&)
  {
    throw Error::DecryptFailed("truncated encrypted buffer");
  }
}

EncryptionFormat::EncryptionMetadata encrypt(uint8_t* encryptedData,
                                             gsl::span<uint8_t const> clearData)
{
  Serialization::varint_write(encryptedData, version());
  Serialization::varint_write(encryptedData + versionSize, encryptedChunkSize);
  auto const key = Crypto::makeSymmetricKey();
  auto const resourceId =
      gsl::span<uint8_t>(encryptedData + versionSize + sizeOfEncryptedChunkSize,
                         ResourceId::arraySize);
  Crypto::randomFill(resourceId);
  auto chunk = encryptedData + ResourceId::arraySize + versionSize +
               sizeOfEncryptedChunkSize;

  for (uint64_t clearDataIndex = 0; clearDataIndex <= clearData.size();
       chunk += encryptedChunkSize, clearDataIndex += clearChunkSize)
  {
    auto const ivSeed = gsl::span<uint8_t>(chunk, Crypto::AeadIv::arraySize);
    Crypto::randomFill(ivSeed);
    auto const numericalIndex = clearDataIndex / clearChunkSize;
    auto const iv = Crypto::deriveIv(Crypto::AeadIv{ivSeed}, numericalIndex);
    auto const nextClearChunkSize = std::min<unsigned long>(
        clearChunkSize, clearData.size() - clearDataIndex);

    Crypto::encryptAead(key,
                        iv.data(),
                        chunk + Crypto::AeadIv::arraySize,
                        clearData.subspan(clearDataIndex, nextClearChunkSize),
                        {});
  }

  return {ResourceId{resourceId}, key};
}

void decrypt(uint8_t* decryptedData,
             Crypto::SymmetricKey const& key,
             gsl::span<uint8_t const> encryptedData)
{
  try
  {
    checkEncryptedFormat(encryptedData);

    auto const versionRemoved =
        Serialization::varint_read(encryptedData).second;
    auto const chunkSizePair = Serialization::varint_read(versionRemoved);
    auto const chunkSize = chunkSizePair.first;
    auto const cipherText = chunkSizePair.second;
    auto const chunks = cipherText.subspan(
        ResourceId::arraySize, cipherText.size() - ResourceId::arraySize);

    for (uint64_t currentSize = 0; currentSize < chunks.size();
         currentSize += chunkSize)
    {
      auto const numericalIndex = currentSize / chunkSize;
      auto const nextclearChunkSize =
          std::min<unsigned long>(chunkSize, chunks.size() - currentSize);
      auto const chunk = chunks.subspan(currentSize, nextclearChunkSize);
      auto const ivSeed =
          Crypto::AeadIv{chunk.subspan(0, Crypto::AeadIv::arraySize)};
      auto const iv = Crypto::deriveIv(ivSeed, numericalIndex);
      auto const cipherText = chunk.subspan(
          Crypto::AeadIv::arraySize, chunk.size() - Crypto::AeadIv::arraySize);
      Crypto::decryptAead(key,
                          iv.data(),
                          decryptedData + numericalIndex * clearChunkSize,
                          cipherText,
                          {});
    }
  }
  catch (std::out_of_range const&)
  {
    throw Error::DecryptFailed("truncated encrypted buffer");
  }
  catch (Crypto::DecryptFailed const& e)
  {
    throw Error::DecryptFailed(e.what());
  }
}

ResourceId extractResourceId(gsl::span<uint8_t const> encryptedData)
{
  try
  {
    checkEncryptedFormat(encryptedData);

    auto const versionPair = Serialization::varint_read(encryptedData);
    auto const cipherText =
        Serialization::varint_read(versionPair.second).second;
    auto const mac = cipherText.subspan(0, ResourceId::arraySize);
    return ResourceId{mac};
  }
  catch (std::out_of_range const&)
  {
    throw Error::DecryptFailed("truncated encrypted buffer");
  }
}
}
}
}
