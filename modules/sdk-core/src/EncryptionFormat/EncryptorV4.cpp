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
constexpr auto sizeOfChunkSize = sizeof(uint32_t);
auto const versionSize = Serialization::varint_size(version());
auto const headerSize = versionSize + sizeOfChunkSize + ResourceId::arraySize;

uint32_t clearChunkSize(uint32_t const encryptedChunkSize)
{
  return encryptedChunkSize - headerSize - Crypto::AeadIv::arraySize -
         Crypto::Mac::arraySize;
}

// version 4 format layout:
// N * chunk of encryptedChunkSize:
// header: [version, 1B] [chunkSize, 4B] [ResourceId, 16B]
// content: [IV seed, 24B] [ciphertext, variable] [MAC, 16B]
void checkEncryptedFormat(gsl::span<uint8_t const> encryptedData)
{
  auto const dataVersionResult = Serialization::varint_read(encryptedData);
  auto const overheadSize = sizeOfChunkSize + ResourceId::arraySize +
                            Crypto::AeadIv::arraySize + Crypto::Mac::arraySize;

  assert(dataVersionResult.first == version());

  if (dataVersionResult.second.size() < overheadSize)
    throw Error::DecryptFailed("truncated encrypted buffer");
}
}

uint64_t encryptedSize(uint64_t clearSize, uint32_t encryptedChunkSize)
{
  auto const chunkSize = clearChunkSize(encryptedChunkSize);
  auto const chunks = clearSize / chunkSize;
  auto const lastClearChunkSize = clearSize % chunkSize;
  return chunks * encryptedChunkSize + headerSize + Crypto::AeadIv::arraySize +
         Crypto::encryptedSize(lastClearChunkSize);
}

uint64_t decryptedSize(gsl::span<uint8_t const> encryptedData)
{
  try
  {
    checkEncryptedFormat(encryptedData);

    auto const versionResult = Serialization::varint_read(encryptedData);
    auto const encryptedChunkSize = Serialization::deserialize<uint32_t>(
        versionResult.second.subspan(0, sizeOfChunkSize));
    if (versionResult.second.size() < sizeOfChunkSize + ResourceId::arraySize)
      throw Error::DecryptFailed("truncated encrypted buffer");
    auto const chunks = encryptedData.size() / encryptedChunkSize;
    auto const lastClearChunkSize =
        (encryptedData.size() % encryptedChunkSize) -
        Crypto::AeadIv::arraySize - headerSize;
    return chunks * clearChunkSize(encryptedChunkSize) +
           Crypto::decryptedSize(lastClearChunkSize);
  }
  catch (std::out_of_range const&)
  {
    throw Error::DecryptFailed("truncated encrypted buffer");
  }
}

EncryptionFormat::EncryptionMetadata encrypt(uint8_t* encryptedData,
                                             gsl::span<uint8_t const> clearData,
                                             uint32_t encryptedChunkSize)
{
  auto const chunkSize = clearChunkSize(encryptedChunkSize);
  auto const key = Crypto::makeSymmetricKey();
  ResourceId resourceId{};
  Crypto::randomFill(resourceId);

  for (uint64_t clearDataIndex = 0; clearDataIndex <= clearData.size();
       encryptedData += encryptedChunkSize, clearDataIndex += chunkSize)
  {
    // write header
    Serialization::varint_write(encryptedData, version());
    Serialization::serialize(encryptedData + versionSize, encryptedChunkSize);
    Serialization::serialize(encryptedData + versionSize + sizeOfChunkSize,
                             resourceId);
    auto chunk = encryptedData + headerSize;

    auto const ivSeed = gsl::span<uint8_t>(chunk, Crypto::AeadIv::arraySize);
    Crypto::randomFill(ivSeed);
    auto const numericalIndex = clearDataIndex / chunkSize;
    auto const iv = Crypto::deriveIv(Crypto::AeadIv{ivSeed}, numericalIndex);
    auto const nextClearChunkSize =
        std::min<unsigned long>(chunkSize, clearData.size() - clearDataIndex);

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

    auto const versionResult = Serialization::varint_read(encryptedData);
    auto const encryptedChunkSize = Serialization::deserialize<uint32_t>(
        versionResult.second.subspan(0, sizeOfChunkSize));

    for (uint64_t currentSize = 0; currentSize < encryptedData.size();
         currentSize += encryptedChunkSize)
    {
      auto const numericalIndex = currentSize / encryptedChunkSize;
      auto const nextClearChunkSize = std::min<unsigned long>(
          encryptedChunkSize, encryptedData.size() - currentSize);
      auto const chunk = encryptedData.subspan(currentSize, nextClearChunkSize);

      // Header
      auto const versionResult = Serialization::varint_read(chunk);
      if (versionResult.first != version())
        throw Error::formatEx<Error::VersionNotSupported>(
            "unsupported version: {:d}", versionResult.first);
      auto const headerRemoved =
          versionResult.second.subspan(ResourceId::arraySize + sizeOfChunkSize);

      auto const ivSeed =
          Crypto::AeadIv{headerRemoved.subspan(0, Crypto::AeadIv::arraySize)};
      auto const iv = Crypto::deriveIv(ivSeed, numericalIndex);
      auto const cipherText = headerRemoved.subspan(Crypto::AeadIv::arraySize);
      Crypto::decryptAead(
          key,
          iv.data(),
          decryptedData + numericalIndex * clearChunkSize(encryptedChunkSize),
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
    auto const mac =
        versionPair.second.subspan(sizeof(uint32_t), ResourceId::arraySize);
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
