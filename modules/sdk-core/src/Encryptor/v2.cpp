#include <Tanker/Encryptor/v2.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>

#include <stdexcept>

using Tanker::Crypto::SimpleResourceId;
using namespace Tanker::Errors;

namespace Tanker
{
namespace
{
constexpr auto versionSize = 1;
constexpr auto overheadSize =
    versionSize + Crypto::AeadIv::arraySize + Crypto::Mac::arraySize;

// version 2 format layout:
// [version, 1B] [IV, 24B] [[ciphertext, variable] [MAC, 16B]]
void checkEncryptedFormat(gsl::span<std::uint8_t const> encryptedData)
{
  if (encryptedData.size() < overheadSize)
    throw formatEx(Errc::InvalidArgument, "truncated encrypted buffer");

  assert(encryptedData[0] == EncryptorV2::version());
}
}

std::uint64_t EncryptorV2::encryptedSize(std::uint64_t clearSize)
{
  return clearSize + overheadSize;
}

std::uint64_t EncryptorV2::decryptedSize(
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  return encryptedData.size() - overheadSize;
}

EncryptionMetadata EncryptorV2::encryptSync(
    gsl::span<std::uint8_t> encryptedData,
    gsl::span<std::uint8_t const> clearData,
    Crypto::SymmetricKey const& key)
{
  encryptedData[0] = version();
  auto const iv = encryptedData.subspan(versionSize, Crypto::AeadIv::arraySize);
  auto const cipherText =
      encryptedData.subspan(versionSize + Crypto::AeadIv::arraySize);
  Crypto::randomFill(iv);
  auto const resourceId =
      Crypto::encryptAead(key, iv, cipherText, clearData, {});
  return EncryptionMetadata{SimpleResourceId(resourceId), key};
}

tc::cotask<EncryptionMetadata> EncryptorV2::encrypt(
    gsl::span<std::uint8_t> encryptedData,
    gsl::span<std::uint8_t const> clearData)
{
  TC_RETURN(encryptSync(encryptedData, clearData, Crypto::makeSymmetricKey()));
}

tc::cotask<std::uint64_t> EncryptorV2::decrypt(
    gsl::span<std::uint8_t> decryptedData,
    Encryptor::ResourceKeyFinder const& keyFinder,
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  auto const resourceId = extractResourceId(encryptedData);
  std::optional key = TC_AWAIT(keyFinder(resourceId));
  auto const iv = encryptedData.subspan(versionSize, Crypto::AeadIv::arraySize);
  auto const cipherText =
      encryptedData.subspan(versionSize + Crypto::AeadIv::arraySize);
  Crypto::tryDecryptAead(key, resourceId, iv, decryptedData, cipherText, {});
  TC_RETURN(decryptedSize(encryptedData));
}

SimpleResourceId EncryptorV2::extractResourceId(
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  auto const cypherText = encryptedData.subspan(versionSize);
  return SimpleResourceId{Crypto::extractMac(cypherText)};
}
}
