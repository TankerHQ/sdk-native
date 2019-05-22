#include <Tanker/EncryptionFormat/EncryptorV2.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Error.hpp>
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
namespace EncryptorV2
{
namespace
{
auto const versionSize = Serialization::varint_size(version());

// version 2 format layout:
// [version, 1B] [IV, 24B] [[ciphertext, variable] [MAC, 16B]]
void checkEncryptedFormat(gsl::span<uint8_t const> encryptedData)
{
  auto const dataVersionResult = Serialization::varint_read(encryptedData);
  auto const overheadSize = Crypto::AeadIv::arraySize + Trustchain::ResourceId::arraySize;

  assert(dataVersionResult.first == version());

  if (dataVersionResult.second.size() < overheadSize)
    throw Error::InvalidArgument("truncated encrypted buffer");
}
}

uint64_t encryptedSize(uint64_t clearSize)
{
  return versionSize + Crypto::AeadIv::arraySize +
         Crypto::encryptedSize(clearSize);
}

uint64_t decryptedSize(gsl::span<uint8_t const> encryptedData)
{
  try
  {
    checkEncryptedFormat(encryptedData);

    auto const versionResult = Serialization::varint_read(encryptedData);
    if (versionResult.second.size() <
        (Crypto::AeadIv::arraySize + Trustchain::ResourceId::arraySize))
      throw Error::InvalidArgument("truncated encrypted buffer");
    return Crypto::decryptedSize(versionResult.second.size() -
                                 Crypto::AeadIv::arraySize);
  }
  catch (std::out_of_range const&)
  {
    throw Error::InvalidArgument("truncated encrypted buffer");
  }
}

EncryptionMetadata encrypt(uint8_t* encryptedData,
                           gsl::span<uint8_t const> clearData)
{
  Serialization::varint_write(encryptedData, version());
  auto const key = Crypto::makeSymmetricKey();
  auto const iv = encryptedData + versionSize;
  Crypto::randomFill(gsl::span<uint8_t>(iv, Crypto::AeadIv::arraySize));
  auto const resourceId = Crypto::encryptAead(
      key,
      iv,
      encryptedData + versionSize + Crypto::AeadIv::arraySize,
      clearData,
      {});
  return {ResourceId(resourceId), key};
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
    auto const iv = versionRemoved.data();
    auto const cipherText = versionRemoved.subspan(Crypto::AeadIv::arraySize);
    Crypto::decryptAead(key, iv, decryptedData, cipherText, {});
  }
  catch (gsl::fail_fast const&)
  {
    throw Error::InvalidArgument("truncated encrypted buffer");
  }
  catch (Errors::Exception const& e)
  {
    if (e.errorCode() == Errors::Errc::DecryptionFailed)
      throw Error::DecryptFailed(e.what());
    throw Error::InvalidArgument(e.what());
  }
}

ResourceId extractResourceId(gsl::span<uint8_t const> encryptedData)
{
  try
  {
    checkEncryptedFormat(encryptedData);

    auto const cypherText = Serialization::varint_read(encryptedData).second;
    return ResourceId{Crypto::extractMac(cypherText)};
  }
  catch (std::out_of_range const&)
  {
    throw Error::InvalidArgument("truncated encrypted buffer");
  }
}
}
}
}
