#include <Tanker/Encryptor/v3.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Varint.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <stdexcept>

using Tanker::Trustchain::ResourceId;

namespace Tanker
{
namespace
{
auto const versionSize = Serialization::varint_size(EncryptorV3::version());

// version 3 format layout:
// [version, 1B] [[ciphertext, variable] [MAC, 16B]]
void checkEncryptedFormat(gsl::span<std::uint8_t const> encryptedData)
{
  auto const dataVersionResult = Serialization::varint_read(encryptedData);
  auto const overheadSize = Trustchain::ResourceId::arraySize;

  assert(dataVersionResult.first == EncryptorV3::version());

  if (dataVersionResult.second.size() < overheadSize)
  {
    throw Errors::formatEx(Errors::Errc::InvalidArgument,
                           "truncated encrypted buffer");
  }
}
}

std::uint64_t EncryptorV3::encryptedSize(std::uint64_t clearSize)
{
  return versionSize + Crypto::encryptedSize(clearSize);
}

std::uint64_t EncryptorV3::decryptedSize(
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  auto const versionResult = Serialization::varint_read(encryptedData);
  return Crypto::decryptedSize(versionResult.second.size());
}

EncryptionMetadata EncryptorV3::encrypt(std::uint8_t* encryptedData,
                                        gsl::span<std::uint8_t const> clearData)
{
  Serialization::varint_write(encryptedData, version());
  auto const key = Crypto::makeSymmetricKey();
  auto const iv = Crypto::AeadIv{};
  auto const resourceId = Crypto::encryptAead(
      key, iv.data(), encryptedData + versionSize, clearData, {});
  return {ResourceId(resourceId), key};
}

void EncryptorV3::decrypt(std::uint8_t* decryptedData,
                          Crypto::SymmetricKey const& key,
                          gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  auto const versionResult = Serialization::varint_read(encryptedData);
  auto const iv = Crypto::AeadIv{};
  Crypto::decryptAead(key, iv.data(), decryptedData, versionResult.second, {});
}

ResourceId EncryptorV3::extractResourceId(
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  auto const cipherText = Serialization::varint_read(encryptedData).second;
  return ResourceId{Crypto::extractMac(cipherText)};
}
}
