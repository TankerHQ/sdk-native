#include <Tanker/Encryptor/v3.hpp>

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
constexpr auto overheadSize = versionSize + Crypto::Mac::arraySize;

// version 3 format layout:
// [version, 1B] [[ciphertext, variable] [MAC, 16B]]
void checkEncryptedFormat(gsl::span<std::uint8_t const> encryptedData)
{
  if (encryptedData.size() < overheadSize)
  {
    throw Errors::formatEx(Errors::Errc::InvalidArgument,
                           "truncated encrypted buffer");
  }

  assert(encryptedData[0] == EncryptorV3::version());
}
}

std::uint64_t EncryptorV3::encryptedSize(std::uint64_t clearSize)
{
  return clearSize + overheadSize;
}

std::uint64_t EncryptorV3::decryptedSize(
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  return encryptedData.size() - overheadSize;
}

tc::cotask<EncryptCacheMetadata> EncryptorV3::encrypt(
    gsl::span<std::uint8_t> encryptedData,
    gsl::span<std::uint8_t const> clearData)
{
  encryptedData[0] = version();
  auto const key = Crypto::makeSymmetricKey();
  auto const iv = Crypto::AeadIv{};
  auto const cipherText = encryptedData.subspan(versionSize);
  auto const resourceId =
      Crypto::encryptAead(key, iv, cipherText, clearData, {});
  TC_RETURN((EncryptCacheMetadata{SimpleResourceId(resourceId), key}));
}

tc::cotask<std::uint64_t> EncryptorV3::decrypt(
    gsl::span<std::uint8_t> decryptedData,
    Encryptor::ResourceKeyFinder const& keyFinder,
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  auto const resourceId = extractResourceId(encryptedData);
  auto const key = TC_AWAIT(keyFinder(resourceId));
  auto const cipherText = encryptedData.subspan(versionSize);
  auto const iv = Crypto::AeadIv{};
  Crypto::tryDecryptAead(key, resourceId, iv, decryptedData, cipherText, {});
  TC_RETURN(decryptedSize(encryptedData));
}

SimpleResourceId EncryptorV3::extractResourceId(
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  auto const cipherText = encryptedData.subspan(versionSize);
  return SimpleResourceId{Crypto::extractMac(cipherText)};
}
}
