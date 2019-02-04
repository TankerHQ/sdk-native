#include <Tanker/Encryptor.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Serialization/Varint.hpp>

#include <fmt/format.h>

#include <stdexcept>

namespace Tanker
{
namespace Encryptor
{
namespace
{
constexpr auto lastVersion = 2u;
auto const maxVersionSize = Serialization::varint_size(lastVersion);

// version 2 format layout:
// [version, 1B] [IV, 24B] [[ciphertext, variable] [MAC, 16B]]
void checkEncryptedFormat(gsl::span<uint8_t const> encryptedData)
{
  auto const dataVersion = Serialization::varint_read(encryptedData).first;
  if (dataVersion != lastVersion)
    throw Error::formatEx<Error::VersionNotSupported>(
        fmt("unsupported version: {:d}"), dataVersion);
  if (encryptedData.size() <
      (Serialization::varint_size(dataVersion) + Crypto::AeadIv::arraySize))
    throw Error::DecryptFailed("truncated encrypted buffer");
}
}

uint64_t encryptedSize(uint64_t clearSize)
{
  return maxVersionSize + Crypto::AeadIv::arraySize +
         Crypto::encryptedSize(clearSize);
}

uint64_t decryptedSize(gsl::span<uint8_t const> encryptedData)
{
  try
  {
    checkEncryptedFormat(encryptedData);
    auto const version = Serialization::varint_read(encryptedData).first;
    auto const versionSize = Serialization::varint_size(version);
    if (encryptedData.size() < versionSize + Crypto::AeadIv::arraySize)
      throw Error::DecryptFailed("truncated encrypted buffer");
    return Crypto::decryptedSize(encryptedData.size() - versionSize -
                                 Crypto::AeadIv::arraySize);
  }
  catch (std::out_of_range const&)
  {
    throw Error::DecryptFailed("truncated encrypted buffer");
  }
}

EncryptionMetadata encrypt(uint8_t* encryptedData,
                           gsl::span<uint8_t const> clearData)
{
  Serialization::varint_write(encryptedData, lastVersion);
  auto const key = Crypto::makeSymmetricKey();
  auto const iv = encryptedData + maxVersionSize;
  Crypto::randomFill(gsl::span<uint8_t>(iv, Crypto::AeadIv::arraySize));
  auto const mac = Crypto::encryptAead(
      key,
      iv,
      encryptedData + maxVersionSize + Crypto::AeadIv::arraySize,
      clearData,
      {});
  return {Crypto::Mac(mac), key};
}

void decrypt(uint8_t* decryptedData,
             Crypto::SymmetricKey const& key,
             gsl::span<uint8_t const> encryptedData)
{
  try
  {
    checkEncryptedFormat(encryptedData);

    auto const version = Serialization::varint_read(encryptedData).first;
    auto const versionSize = Serialization::varint_size(version);
    auto const iv = encryptedData.subspan(versionSize).data();
    auto const cipherText =
        encryptedData.subspan(versionSize + Crypto::AeadIv::arraySize);
    Crypto::decryptAead(key, iv, decryptedData, cipherText, {});
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

    auto const version = Serialization::varint_read(encryptedData).first;
    auto const versionSize = Serialization::varint_size(version);
    auto const cipherText =
        encryptedData.subspan(versionSize, encryptedData.size() - versionSize);
    return Crypto::Mac{Crypto::extractMac(cipherText)};
  }
  catch (std::out_of_range const&)
  {
    throw Error::DecryptFailed("truncated encrypted buffer");
  }
}
}
}
