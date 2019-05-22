#include <Tanker/EncryptionFormat/EncryptorV3.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Varint.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <stdexcept>

using Tanker::Trustchain::ResourceId;

namespace Tanker
{
namespace EncryptionFormat
{
namespace EncryptorV3
{
namespace
{
auto const versionSize = Serialization::varint_size(version());

// version 3 format layout:
// [version, 1B] [[ciphertext, variable] [MAC, 16B]]
void checkEncryptedFormat(gsl::span<uint8_t const> encryptedData)
{
  auto const dataVersionResult = Serialization::varint_read(encryptedData);
  auto const overheadSize = Trustchain::ResourceId::arraySize;

  assert(dataVersionResult.first == version());

  if (dataVersionResult.second.size() < overheadSize)
    throw Error::InvalidArgument("truncated encrypted buffer");
}
}

uint64_t encryptedSize(uint64_t clearSize)
{
  return versionSize + Crypto::encryptedSize(clearSize);
}

uint64_t decryptedSize(gsl::span<uint8_t const> encryptedData)
{
  try
  {
    checkEncryptedFormat(encryptedData);

    auto const versionResult = Serialization::varint_read(encryptedData);
    if (versionResult.second.size() < Trustchain::ResourceId::arraySize)
      throw Error::InvalidArgument("truncated encrypted buffer");
    return Crypto::decryptedSize(versionResult.second.size());
  }
  catch (gsl::fail_fast const&)
  {
    throw Error::InvalidArgument("truncated encrypted buffer");
  }
}

EncryptionMetadata encrypt(uint8_t* encryptedData,
                           gsl::span<uint8_t const> clearData)
{
  Serialization::varint_write(encryptedData, version());
  auto const key = Crypto::makeSymmetricKey();
  auto const iv = Crypto::AeadIv{};
  auto const resourceId = Crypto::encryptAead(
      key, iv.data(), encryptedData + versionSize, clearData, {});
  return {ResourceId(resourceId), key};
}

void decrypt(uint8_t* decryptedData,
             Crypto::SymmetricKey const& key,
             gsl::span<uint8_t const> encryptedData)
{
  try
  {
    checkEncryptedFormat(encryptedData);

    auto const versionResult = Serialization::varint_read(encryptedData);
    auto const iv = Crypto::AeadIv{};
    Crypto::decryptAead(
        key, iv.data(), decryptedData, versionResult.second, {});
  }
  catch (std::out_of_range const&)
  {
    throw Error::InvalidArgument("truncated encrypted buffer");
  }
  catch (Errors::Exception const& e)
  {
    throw Error::DecryptFailed(e.what());
  }
}

ResourceId extractResourceId(gsl::span<uint8_t const> encryptedData)
{
  try
  {
    checkEncryptedFormat(encryptedData);

    auto const cipherText = Serialization::varint_read(encryptedData).second;
    return ResourceId{Crypto::extractMac(cipherText)};
  }
  catch (std::out_of_range const&)
  {
    throw Error::InvalidArgument("truncated encrypted buffer");
  }
}
}
}
}
