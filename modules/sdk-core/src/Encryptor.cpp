#include <Tanker/Encryptor.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/EncryptionFormat/EncryptorV2.hpp>
#include <Tanker/EncryptionFormat/EncryptorV3.hpp>
#include <Tanker/EncryptionFormat/EncryptorV4.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Serialization/Varint.hpp>

using Tanker::Trustchain::ResourceId;

namespace Tanker
{
using namespace EncryptionFormat;
using namespace Errors;

namespace Encryptor
{
namespace
{
constexpr auto hugeDataThreshold = 1024 * 1024;

constexpr bool isHugeClearData(uint64_t dataSize)
{
  return dataSize > hugeDataThreshold;
}
}

uint64_t encryptedSize(uint64_t clearSize)
{
  if (isHugeClearData(clearSize))
    return EncryptorV4::encryptedSize(clearSize);
  return EncryptorV3::encryptedSize(clearSize);
}

uint64_t decryptedSize(gsl::span<uint8_t const> encryptedData)
{
  auto const version = Serialization::varint_read(encryptedData).first;

  switch (version)
  {
  case EncryptorV2::version():
    return EncryptorV2::decryptedSize(encryptedData);
  case EncryptorV3::version():
    return EncryptorV3::decryptedSize(encryptedData);
  case EncryptorV4::version():
    return EncryptorV4::decryptedSize(encryptedData);
  default:
    throw formatEx(
        Errc::InvalidArgument, TFMT("unsupported version: {:d}"), version);
  }
}

EncryptionFormat::EncryptionMetadata encrypt(uint8_t* encryptedData,
                                             gsl::span<uint8_t const> clearData)
{
  if (isHugeClearData(clearData.size()))
    return EncryptorV4::encrypt(encryptedData, clearData);
  return EncryptorV3::encrypt(encryptedData, clearData);
}

void decrypt(uint8_t* decryptedData,
             Crypto::SymmetricKey const& key,
             gsl::span<uint8_t const> encryptedData)
{
  auto const version = Serialization::varint_read(encryptedData).first;

  switch (version)
  {
  case EncryptorV2::version():
    return EncryptorV2::decrypt(decryptedData, key, encryptedData);
  case EncryptorV3::version():
    return EncryptorV3::decrypt(decryptedData, key, encryptedData);
  case EncryptorV4::version():
    return EncryptorV4::decrypt(decryptedData, key, encryptedData);
  default:
    throw formatEx(
        Errc::InvalidArgument, TFMT("unsupported version: {:d}"), version);
  }
}

ResourceId extractResourceId(gsl::span<uint8_t const> encryptedData)
{
  auto const version = Serialization::varint_read(encryptedData).first;

  switch (version)
  {
  case EncryptorV2::version():
    return EncryptorV2::extractResourceId(encryptedData);
  case EncryptorV3::version():
    return EncryptorV3::extractResourceId(encryptedData);
  case EncryptorV4::version():
    return EncryptorV4::extractResourceId(encryptedData);
  default:
    throw formatEx(
        Errc::InvalidArgument, TFMT("unsupported version: {:d}"), version);
  }
}
}
}
