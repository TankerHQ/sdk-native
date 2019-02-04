#include <Tanker/Encryptor.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/EncryptionFormat/EncryptorV2.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Serialization/Varint.hpp>

namespace Tanker
{
using namespace EncryptionFormat;

namespace Encryptor
{
uint64_t encryptedSize(uint64_t clearSize)
{
  return EncryptorV2::encryptedSize(clearSize);
}

uint64_t decryptedSize(gsl::span<uint8_t const> encryptedData)
{
  try
  {
    auto const version = Serialization::varint_read(encryptedData).first;

    switch (version)
    {
    case EncryptorV2::version():
      return EncryptorV2::decryptedSize(encryptedData);
    default:
      throw Error::formatEx<Error::VersionNotSupported>(
          "unsupported version: {:d}", version);
    }
  }
  catch (std::out_of_range const&)
  {
    throw Error::DecryptFailed("truncated encrypted buffer");
  }
}

EncryptionFormat::EncryptionMetadata encrypt(uint8_t* encryptedData,
                                             gsl::span<uint8_t const> clearData)
{
  return EncryptorV2::encrypt(encryptedData, clearData);
}

void decrypt(uint8_t* decryptedData,
             Crypto::SymmetricKey const& key,
             gsl::span<uint8_t const> encryptedData)
{
  try
  {
    auto const version = Serialization::varint_read(encryptedData).first;

    switch (version)
    {
    case EncryptorV2::version():
      return EncryptorV2::decrypt(decryptedData, key, encryptedData);
    default:
      throw Error::formatEx<Error::VersionNotSupported>(
          "unsupported version: {:d}", version);
    }
  }
  catch (std::out_of_range const&)
  {
    throw Error::DecryptFailed("truncated encrypted buffer");
  }
}

ResourceId extractResourceId(gsl::span<uint8_t const> encryptedData)
{
  try
  {
    auto const version = Serialization::varint_read(encryptedData).first;

    switch (version)
    {
    case EncryptorV2::version():
      return EncryptorV2::extractResourceId(encryptedData);
    default:
      throw Error::formatEx<Error::VersionNotSupported>(
          "unsupported version: {:d}", version);
    }
  }
  catch (std::out_of_range const&)
  {
    throw Error::DecryptFailed("truncated encrypted buffer");
  }
}
}
}
