#include <Tanker/Encryptor/v3.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <stdexcept>

using Tanker::Trustchain::ResourceId;

namespace Tanker
{
namespace
{
auto const versionSize = 1;
auto const overheadSize = versionSize + Crypto::Mac::arraySize;

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

tc::cotask<EncryptionMetadata> EncryptorV3::encrypt(
    std::uint8_t* encryptedData, gsl::span<std::uint8_t const> clearData)
{
  encryptedData[0] = version();
  auto const key = Crypto::makeSymmetricKey();
  auto const iv = Crypto::AeadIv{};
  auto const resourceId = Crypto::encryptAead(
      key, iv.data(), encryptedData + versionSize, clearData, {});
  TC_RETURN((EncryptionMetadata{ResourceId(resourceId), key}));
}

tc::cotask<void> EncryptorV3::decrypt(
    std::uint8_t* decryptedData,
    Crypto::SymmetricKey const& key,
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  auto const cipherText = encryptedData.subspan(versionSize);
  auto const iv = Crypto::AeadIv{};
  Crypto::decryptAead(key, iv.data(), decryptedData, cipherText, {});
  TC_RETURN();
}

ResourceId EncryptorV3::extractResourceId(
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  auto const cipherText = encryptedData.subspan(versionSize);
  return ResourceId{Crypto::extractMac(cipherText)};
}
}
