#include <Tanker/Encryptor.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Padding.hpp>
#include <Tanker/Encryptor/v2.hpp>
#include <Tanker/Encryptor/v3.hpp>
#include <Tanker/Encryptor/v4.hpp>
#include <Tanker/Encryptor/v5.hpp>
#include <Tanker/Encryptor/v6.hpp>
#include <Tanker/Encryptor/v7.hpp>
#include <Tanker/Encryptor/v8.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Errors/Errc.hpp>

#include <Tanker/Streams/Header.hpp>

using Tanker::Trustchain::ResourceId;

namespace Tanker
{
using namespace Errors;

namespace Encryptor
{
namespace
{
constexpr auto STREAM_THRESHOLD = 1024 * 1024;

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
  case EncryptorV6::version():
    return std::forward<Callable>(cb)(EncryptorV6{});
  case EncryptorV7::version():
    return std::forward<Callable>(cb)(EncryptorV7{});
  case EncryptorV8::version():
    return std::forward<Callable>(cb)(EncryptorV8{});
  default:
    throw Errors::Exception(make_error_code(Errc::InvalidArgument),
                            "invalid encrypted data");
  }
}
}

bool isHugeClearData(uint64_t dataSize, std::optional<uint32_t> paddingStep)
{
  return Padding::paddedFromClearSize(dataSize, paddingStep) >=
         STREAM_THRESHOLD;
}

uint64_t encryptedSize(uint64_t clearSize, std::optional<uint32_t> paddingStep)
{
  if (isHugeClearData(clearSize, paddingStep))
  {
    if (paddingStep == Padding::Off)
      return EncryptorV4::encryptedSize(clearSize);
    else
      return EncryptorV8::encryptedSize(clearSize, paddingStep);
  }
  else
  {
    if (paddingStep == Padding::Off)
      return EncryptorV3::encryptedSize(clearSize);
    else
      return EncryptorV6::encryptedSize(clearSize, paddingStep);
  }
}

uint64_t decryptedSize(gsl::span<uint8_t const> encryptedData)
{
  if (encryptedData.size() < 1)
    throw Errors::Exception(Serialization::Errc::TruncatedInput,
                            "Could not read version");

  auto const version = encryptedData[0];

  return performEncryptorAction(version, [=](auto encryptor) {
    return encryptor.decryptedSize(encryptedData);
  });
}

tc::cotask<EncryptionMetadata> encrypt(gsl::span<uint8_t> encryptedData,
                                       gsl::span<uint8_t const> clearData,
                                       std::optional<uint32_t> paddingStep)
{
  if (isHugeClearData(clearData.size(), paddingStep))
  {
    if (paddingStep == Padding::Off)
      TC_RETURN(TC_AWAIT(EncryptorV4::encrypt(encryptedData, clearData)));
    else
      TC_RETURN(TC_AWAIT(
          EncryptorV8::encrypt(encryptedData, clearData, paddingStep)));
  }
  else
  {
    if (paddingStep == Padding::Off)
      TC_RETURN(TC_AWAIT(EncryptorV3::encrypt(encryptedData, clearData)));
    else
      TC_RETURN(TC_AWAIT(
          EncryptorV6::encrypt(encryptedData, clearData, paddingStep)));
  }
}

tc::cotask<uint64_t> decrypt(gsl::span<uint8_t> decryptedData,
                             Crypto::SymmetricKey const& key,
                             gsl::span<uint8_t const> encryptedData)
{
  if (encryptedData.size() < 1)
    throw Errors::Exception(Serialization::Errc::TruncatedInput,
                            "Could not read version");

  auto const version = encryptedData[0];

  TC_RETURN(TC_AWAIT(performEncryptorAction(
      version, [&](auto encryptor) -> tc::cotask<uint64_t> {
        TC_RETURN(
            TC_AWAIT(encryptor.decrypt(decryptedData, key, encryptedData)));
      })));
}

ResourceId extractResourceId(gsl::span<uint8_t const> encryptedData)
{
  if (encryptedData.size() < 1)
    throw Errors::Exception(Serialization::Errc::TruncatedInput,
                            "Could not read version");

  auto const version = encryptedData[0];

  return performEncryptorAction(version, [&](auto encryptor) {
    return encryptor.extractResourceId(encryptedData);
  });
}
}
}
