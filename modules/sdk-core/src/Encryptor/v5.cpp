#include <Tanker/Encryptor/v5.hpp>

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
constexpr auto versionSize = 1;
constexpr auto overheadSize = versionSize + ResourceId::arraySize +
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

tc::cotask<EncryptionMetadata> EncryptorV5::encrypt(
    std::uint8_t* encryptedData,
    gsl::span<std::uint8_t const> clearData,
    ResourceId const& resourceId,
    Crypto::SymmetricKey const& key)
{
  encryptedData[0] = version();
  std::copy(resourceId.begin(), resourceId.end(), encryptedData + versionSize);
  auto const iv = encryptedData + versionSize + ResourceId::arraySize;
  Crypto::randomFill(gsl::make_span(iv, Crypto::AeadIv::arraySize));
  Crypto::encryptAead(key,
                      iv,
                      encryptedData + versionSize + ResourceId::arraySize +
                          Crypto::AeadIv::arraySize,
                      clearData,
                      resourceId);
  TC_RETURN((EncryptionMetadata{resourceId, key}));
}

tc::cotask<void> EncryptorV5::decrypt(
    std::uint8_t* decryptedData,
    Crypto::SymmetricKey const& key,
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  auto const resourceId =
      encryptedData.subspan(versionSize, ResourceId::arraySize);
  auto const iv = encryptedData.subspan(versionSize + ResourceId::arraySize);
  auto const data = encryptedData.subspan(versionSize + ResourceId::arraySize +
                                          Crypto::AeadIv::arraySize);
  Crypto::decryptAead(key, iv.data(), decryptedData, data, resourceId);
  TC_RETURN();
}

ResourceId EncryptorV5::extractResourceId(
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  return ResourceId{encryptedData.subspan(versionSize, ResourceId::arraySize)};
}
}
