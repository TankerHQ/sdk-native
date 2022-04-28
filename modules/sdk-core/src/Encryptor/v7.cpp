#include <Tanker/Encryptor/v7.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Padding.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Varint.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <gsl/gsl-lite.hpp>
#include <range/v3/algorithm/copy.hpp>
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

// version 7 format layout:
// [version, 1B] [resourceid, 16B] [iv, 24B] [[ciphertext, variable] [MAC, 16B]]
void checkEncryptedFormat(gsl::span<std::uint8_t const> encryptedData)
{
  if (encryptedData.size() < overheadSize)
  {
    throw Errors::formatEx(Errors::Errc::InvalidArgument,
                           "truncated encrypted buffer");
  }

  assert(encryptedData[0] == EncryptorV7::version());
}
}

std::uint64_t EncryptorV7::encryptedSize(
    std::uint64_t clearSize, std::optional<std::uint32_t> paddingStep)
{
  return versionSize + ResourceId::arraySize + Crypto::AeadIv::arraySize +
         Crypto::encryptedSize(
             Padding::paddedFromClearSize(clearSize, paddingStep));
}

std::uint64_t EncryptorV7::decryptedSize(
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  return encryptedData.size() - overheadSize;
}

tc::cotask<EncryptionMetadata> EncryptorV7::encrypt(
    gsl::span<std::uint8_t> encryptedData,
    gsl::span<std::uint8_t const> clearData,
    ResourceId const& resourceId,
    Crypto::SymmetricKey const& key,
    std::optional<std::uint32_t> paddingStep)
{
  encryptedData[0] = version();
  ranges::copy(resourceId, encryptedData.data() + versionSize);
  auto const iv = encryptedData.subspan(versionSize + ResourceId::arraySize,
                                        Crypto::AeadIv::arraySize);
  Crypto::randomFill(iv);
  auto const associatedData =
      encryptedData.subspan(0, versionSize + ResourceId::arraySize);
  auto const cipherText = encryptedData.subspan(
      versionSize + ResourceId::arraySize + Crypto::AeadIv::arraySize);
  auto const paddedData = Padding::padClearData(clearData, paddingStep);
  Crypto::encryptAead(key, iv, cipherText, paddedData, associatedData);
  TC_RETURN((EncryptionMetadata{resourceId, key}));
}

tc::cotask<std::uint64_t> EncryptorV7::decrypt(
    gsl::span<uint8_t> decryptedData,
    Crypto::SymmetricKey const& key,
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  auto const associatedData =
      encryptedData.subspan(0, versionSize + ResourceId::arraySize);
  auto const iv = encryptedData.subspan(versionSize + ResourceId::arraySize,
                                        Crypto::AeadIv::arraySize);
  auto const data = encryptedData.subspan(versionSize + ResourceId::arraySize +
                                          Crypto::AeadIv::arraySize);

  Crypto::decryptAead(key, iv, decryptedData, data, associatedData);

  TC_RETURN(Padding::unpaddedSize(decryptedData));
}

ResourceId EncryptorV7::extractResourceId(
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  return ResourceId{encryptedData.subspan(versionSize, ResourceId::arraySize)};
}
}
