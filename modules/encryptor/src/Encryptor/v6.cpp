#include <Tanker/Encryptor/v6.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Padding.hpp>
#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>

#include <cstdint>
#include <gsl/gsl-lite.hpp>
#include <iterator>
#include <stdexcept>
#include <utility>
#include <vector>

using Tanker::Crypto::SimpleResourceId;

namespace Tanker
{
namespace
{
constexpr auto versionSize = 1;
constexpr auto overheadSize = versionSize + Crypto::Mac::arraySize;

// version 6 format layout:
// [version, 1B] [[ciphertext, variable] [MAC, 16B]]
void checkEncryptedFormat(gsl::span<std::uint8_t const> encryptedData)
{
  if (encryptedData.size() < overheadSize)
  {
    throw Errors::formatEx(Errors::Errc::InvalidArgument, "truncated encrypted buffer");
  }

  assert(encryptedData[0] == EncryptorV6::version());
}
}

std::uint64_t EncryptorV6::encryptedSize(std::uint64_t clearSize, std::optional<std::uint32_t> paddingStep)
{
  return versionSize + Crypto::encryptedSize(Padding::paddedFromClearSize(clearSize, paddingStep));
}

std::uint64_t EncryptorV6::decryptedSize(gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  return encryptedData.size() - overheadSize;
}

tc::cotask<EncryptCacheMetadata> EncryptorV6::encrypt(gsl::span<std::uint8_t> encryptedData,
                                                      gsl::span<std::uint8_t const> clearData,
                                                      std::optional<std::uint32_t> paddingStep)
{
  encryptedData[0] = version();
  auto const key = Crypto::makeSymmetricKey();
  auto const iv = Crypto::AeadIv{};
  auto const cipherText = encryptedData.subspan(versionSize);
  auto const paddedData = Padding::padClearData(clearData, paddingStep);
  auto const additionalData = encryptedData.subspan(0, versionSize);
  auto const resourceId = Crypto::encryptAead(key, iv, cipherText, paddedData, additionalData);

  TC_RETURN((EncryptCacheMetadata{SimpleResourceId(resourceId), key}));
}

tc::cotask<std::uint64_t> EncryptorV6::decrypt(gsl::span<uint8_t> decryptedData,
                                               Encryptor::ResourceKeyFinder const& keyFinder,
                                               gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  auto const resourceId = extractResourceId(encryptedData);
  std::optional key = TC_AWAIT(keyFinder(resourceId));
  auto const cipherText = encryptedData.subspan(versionSize);
  auto const iv = Crypto::AeadIv{};
  auto const additionalData = encryptedData.subspan(0, versionSize);
  Crypto::tryDecryptAead(key, resourceId, iv, decryptedData, cipherText, additionalData);

  TC_RETURN(Padding::unpaddedSize(decryptedData));
}

SimpleResourceId EncryptorV6::extractResourceId(gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  auto const cipherText = encryptedData.subspan(versionSize);
  return SimpleResourceId{Crypto::extractMac(cipherText)};
}
}
