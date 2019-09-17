#include <Tanker/Encryptor/v5.hpp>

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
auto const versionSize = Serialization::varint_size(EncryptorV5::version());

// version 5 format layout:
// [version, 1B] [resourceid, 16B] [iv, 24B] [[ciphertext, variable] [MAC, 16B]]
void checkEncryptedFormat(gsl::span<std::uint8_t const> encryptedData)
{
  auto const dataVersionResult = Serialization::varint_read(encryptedData);
  auto const overheadSize = Trustchain::ResourceId::arraySize +
                            Crypto::AeadIv::arraySize +
                            Trustchain::ResourceId::arraySize;

  assert(dataVersionResult.first == EncryptorV5::version());

  if (dataVersionResult.second.size() < overheadSize)
  {
    throw Errors::formatEx(Errors::Errc::InvalidArgument,
                           "truncated encrypted buffer");
  }
}
}

std::uint64_t EncryptorV5::encryptedSize(std::uint64_t clearSize)
{
  return versionSize + Trustchain::ResourceId::arraySize +
         Crypto::AeadIv::arraySize + Crypto::encryptedSize(clearSize);
}

std::uint64_t EncryptorV5::decryptedSize(
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  auto const versionResult = Serialization::varint_read(encryptedData);
  return Crypto::decryptedSize(versionResult.second.size() -
                               Trustchain::ResourceId::arraySize -
                               Crypto::AeadIv::arraySize);
}

EncryptionMetadata EncryptorV5::encrypt(
    std::uint8_t* encryptedData,
    gsl::span<std::uint8_t const> clearData,
    Trustchain::ResourceId const& resourceId,
    Crypto::SymmetricKey const& key)
{
  Serialization::varint_write(encryptedData, version());
  std::copy(resourceId.begin(), resourceId.end(), encryptedData + versionSize);
  auto const iv =
      encryptedData + versionSize + Trustchain::ResourceId::arraySize;
  Crypto::randomFill(gsl::make_span(iv, Crypto::AeadIv::arraySize));
  Crypto::encryptAead(key,
                      iv,
                      encryptedData + versionSize +
                          Trustchain::ResourceId::arraySize +
                          Crypto::AeadIv::arraySize,
                      clearData,
                      resourceId);
  return {ResourceId(resourceId), key};
}

void EncryptorV5::decrypt(std::uint8_t* decryptedData,
                          Crypto::SymmetricKey const& key,
                          gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  auto const resourceId =
      encryptedData.subspan(versionSize, Trustchain::ResourceId::arraySize);
  auto const iv =
      encryptedData.subspan(versionSize + Trustchain::ResourceId::arraySize);
  auto const data =
      encryptedData.subspan(versionSize + Trustchain::ResourceId::arraySize +
                            Crypto::AeadIv::arraySize);
  Crypto::decryptAead(key, iv.data(), decryptedData, data, resourceId);
}

ResourceId EncryptorV5::extractResourceId(
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  return ResourceId{encryptedData.subspan(versionSize, ResourceId::arraySize)};
}
}
