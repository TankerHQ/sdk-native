#include <Tanker/Encryptor/v5.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>

#include <stdexcept>

using Tanker::Crypto::SimpleResourceId;

namespace Tanker
{
namespace
{
constexpr auto versionSize = 1;
constexpr auto overheadSize = versionSize + SimpleResourceId::arraySize +
                              Crypto::AeadIv::arraySize +
                              Crypto::Mac::arraySize;

// version 5 format layout:
// [version, 1B] [resourceid, 16B] [iv, 24B] [[ciphertext, variable] [MAC, 16B]]
void checkEncryptedFormat(gsl::span<std::uint8_t const> encryptedData)
{
  if (encryptedData.size() < overheadSize)
  {
    throw Errors::formatEx(Errors::Errc::InvalidArgument,
                           "truncated encrypted buffer");
  }

  assert(encryptedData[0] == EncryptorV5::version());
}
}

std::uint64_t EncryptorV5::encryptedSize(std::uint64_t clearSize)
{
  return clearSize + overheadSize;
}

std::uint64_t EncryptorV5::decryptedSize(
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  return encryptedData.size() - overheadSize;
}

tc::cotask<EncryptCacheMetadata> EncryptorV5::encrypt(
    gsl::span<std::uint8_t> encryptedData,
    gsl::span<std::uint8_t const> clearData,
    SimpleResourceId const& resourceId,
    Crypto::SymmetricKey const& key)
{
  encryptedData[0] = version();
  std::copy(
      resourceId.begin(), resourceId.end(), encryptedData.data() + versionSize);
  auto const iv = encryptedData.subspan(
      versionSize + SimpleResourceId::arraySize, Crypto::AeadIv::arraySize);
  auto const cipherText = encryptedData.subspan(
      versionSize + SimpleResourceId::arraySize + Crypto::AeadIv::arraySize);
  Crypto::randomFill(iv);
  Crypto::encryptAead(key, iv, cipherText, clearData, resourceId);
  TC_RETURN((EncryptCacheMetadata{resourceId, key}));
}

tc::cotask<std::uint64_t> EncryptorV5::decrypt(
    gsl::span<std::uint8_t> decryptedData,
    Encryptor::ResourceKeyFinder const& keyFinder,
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  auto const resourceId = extractResourceId(encryptedData);
  std::optional key = TC_AWAIT(keyFinder(resourceId));
  auto const iv = encryptedData.subspan(
      versionSize + SimpleResourceId::arraySize, Crypto::AeadIv::arraySize);
  auto const data = encryptedData.subspan(
      versionSize + SimpleResourceId::arraySize + Crypto::AeadIv::arraySize);
  Crypto::tryDecryptAead(key, resourceId, iv, decryptedData, data, resourceId);
  TC_RETURN(decryptedSize(encryptedData));
}

SimpleResourceId EncryptorV5::extractResourceId(
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  return SimpleResourceId{
      encryptedData.subspan(versionSize, SimpleResourceId::arraySize)};
}
}
