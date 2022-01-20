#include <Tanker/Encryptor.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Encryptor/v2.hpp>
#include <Tanker/Encryptor/v3.hpp>
#include <Tanker/Encryptor/v4.hpp>
#include <Tanker/Encryptor/v5.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>

#include <Tanker/Serialization/Varint.hpp>
#include <Tanker/Streams/Header.hpp>

using Tanker::Trustchain::ResourceId;

namespace Tanker
{
using namespace Errors;

namespace Encryptor
{
namespace
{
template <typename Callable>
decltype(auto) performEncryptorAction(std::uint32_t version, Callable&& cb)
{
  switch (version)
  {
  case EncryptorV2::version():
    return std::forward<Callable>(cb)(EncryptorV2{});
  case EncryptorV3::version():
    return std::forward<Callable>(cb)(EncryptorV3{});
  case EncryptorV4::version():
    return std::forward<Callable>(cb)(EncryptorV4{});
  case EncryptorV5::version():
    return std::forward<Callable>(cb)(EncryptorV5{});
  default:
    throw Errors::Exception(make_error_code(Errc::InvalidArgument),
                            "invalid encrypted data");
  }
}
}

bool isHugeClearData(uint64_t dataSize)
{
  return dataSize > Streams::Header::defaultEncryptedChunkSize;
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

  return performEncryptorAction(version, [=](auto encryptor) {
    return encryptor.decryptedSize(encryptedData);
  });
}

tc::cotask<EncryptionMetadata> encrypt(uint8_t* encryptedData,
                                       gsl::span<uint8_t const> clearData)
{
  if (isHugeClearData(clearData.size()))
    TC_RETURN(TC_AWAIT(EncryptorV4::encrypt(encryptedData, clearData)));
  TC_RETURN(TC_AWAIT(EncryptorV3::encrypt(encryptedData, clearData)));
}

tc::cotask<void> decrypt(gsl::span<uint8_t> decryptedData,
                         Crypto::SymmetricKey const& key,
                         gsl::span<uint8_t const> encryptedData)
{
  auto const version = Serialization::varint_read(encryptedData).first;

  return performEncryptorAction(version, [&](auto encryptor) {
    return encryptor.decrypt(decryptedData, key, encryptedData);
  });
}

ResourceId extractResourceId(gsl::span<uint8_t const> encryptedData)
{
  auto const version = Serialization::varint_read(encryptedData).first;

  return performEncryptorAction(version, [&](auto encryptor) {
    return encryptor.extractResourceId(encryptedData);
  });
}
}
}
