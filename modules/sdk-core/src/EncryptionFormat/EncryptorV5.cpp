#include <Tanker/EncryptionFormat/EncryptorV5.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Varint.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <stdexcept>

using Tanker::Trustchain::ResourceId;

namespace Tanker
{
namespace EncryptionFormat
{
namespace EncryptorV5
{
namespace
{
auto const versionSize = Serialization::varint_size(version());

// version 5 format layout:
// [version, 1B] [resourceid, 16B] [iv, 24B] [[ciphertext, variable] [MAC, 16B]]
void checkEncryptedFormat(gsl::span<uint8_t const> encryptedData)
{
  auto const dataVersionResult = Serialization::varint_read(encryptedData);
  auto const overheadSize = Trustchain::ResourceId::arraySize +
                            Crypto::AeadIv::arraySize +
                            Trustchain::ResourceId::arraySize;

  assert(dataVersionResult.first == version());

  if (dataVersionResult.second.size() < overheadSize)
  {
    throw Errors::formatEx(Errors::Errc::InvalidArgument,
                           "truncated encrypted buffer");
  }
}
}

uint64_t encryptedSize(uint64_t clearSize)
{
  return versionSize + Trustchain::ResourceId::arraySize +
         Crypto::AeadIv::arraySize + Crypto::encryptedSize(clearSize);
}

uint64_t decryptedSize(gsl::span<uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  auto const versionResult = Serialization::varint_read(encryptedData);
  return Crypto::decryptedSize(versionResult.second.size() -
                               Trustchain::ResourceId::arraySize -
                               Crypto::AeadIv::arraySize);
}

EncryptionMetadata encrypt(uint8_t* encryptedData,
                           gsl::span<uint8_t const> clearData,
                           Trustchain::ResourceId const& resourceId,
                           Crypto::SymmetricKey const& key)
{
  Serialization::varint_write(encryptedData, version());
  std::copy(resourceId.begin(), resourceId.end(), encryptedData + versionSize);
  auto const iv =
      encryptedData + versionSize + Trustchain::ResourceId::arraySize;
  Crypto::randomFill(gsl::span<uint8_t>(iv, Crypto::AeadIv::arraySize));
  Crypto::encryptAead(key,
                      iv,
                      encryptedData + versionSize +
                          Trustchain::ResourceId::arraySize +
                          Crypto::AeadIv::arraySize,
                      clearData,
                      resourceId);
  return {ResourceId(resourceId), key};
}

void decrypt(uint8_t* decryptedData,
             Crypto::SymmetricKey const& key,
             gsl::span<uint8_t const> encryptedData)
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

ResourceId extractResourceId(gsl::span<uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  return ResourceId{encryptedData.subspan(versionSize, ResourceId::arraySize)};
}
}
}
}
