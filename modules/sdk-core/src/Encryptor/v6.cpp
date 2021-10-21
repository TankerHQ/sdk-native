#include <Tanker/Encryptor/v6.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Encryptor/Padding.hpp>
#include <Tanker/Encryptor/v3.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Varint.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <cstdint>
#include <gsl/gsl-lite.hpp>
#include <iterator>
#include <stdexcept>
#include <utility>
#include <vector>

using Tanker::Trustchain::ResourceId;

namespace Tanker
{
namespace
{
auto const versionSize = Serialization::varint_size(EncryptorV6::version());

// version 6 format layout:
// [version, 1B] [[ciphertext, variable] [MAC, 16B]]
void checkEncryptedFormat(gsl::span<std::uint8_t const> encryptedData)
{
  auto const dataVersionResult = Serialization::varint_read(encryptedData);
  auto const overheadSize = Trustchain::ResourceId::arraySize;

  assert(dataVersionResult.first == version());

  if (dataVersionResult.second.size() < overheadSize)
  {
    throw Errors::formatEx(Errors::Errc::InvalidArgument,
                           "truncated encrypted buffer");
  }
}
}

std::uint64_t EncryptorV6::encryptedSize(
    std::uint64_t clearSize, std::optional<std::uint32_t> paddingStep)
{
  return versionSize + Crypto::encryptedSize(Padding::paddedFromClearSize(
                           clearSize, paddingStep));
}

std::uint64_t EncryptorV6::decryptedSize(
    gsl::span<std::uint8_t const> encryptedData)
{
  // -1 is the padding byte (0x80)
  return EncryptorV3::decryptedSize(encryptedData) - 1ULL;
}

tc::cotask<EncryptionMetadata> EncryptorV6::encrypt(
    std::uint8_t* encryptedData,
    gsl::span<std::uint8_t const> clearData,
    std::optional<std::uint32_t> paddingStep)
{
  auto const endOfVersion =
      Serialization::varint_write(encryptedData, version());
  auto const key = Crypto::makeSymmetricKey();
  auto const iv = Crypto::AeadIv{};
  auto const paddedData = Padding::padClearData(clearData, paddingStep);
  gsl::span<std::uint8_t const> additionalData(encryptedData, endOfVersion);
  auto const resourceId = Crypto::encryptAead(
      key, iv.data(), encryptedData + versionSize, paddedData, additionalData);

  TC_RETURN((EncryptionMetadata{ResourceId(resourceId), key}));
}

tc::cotask<std::uint64_t> EncryptorV6::decrypt(
    std::uint8_t* decryptedData,
    Crypto::SymmetricKey const& key,
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  auto const versionResult = Serialization::varint_read(encryptedData);
  auto const iv = Crypto::AeadIv{};
  gsl::span<std::uint8_t const> additionalData(encryptedData.data(),
                                               versionResult.second.data());
  Crypto::decryptAead(
      key, iv.data(), decryptedData, versionResult.second, additionalData);

  auto const paddedSize = EncryptorV3::decryptedSize(encryptedData);
  TC_RETURN(Padding::unpaddedSize(gsl::make_span(decryptedData, paddedSize)));
}

ResourceId EncryptorV6::extractResourceId(
    gsl::span<std::uint8_t const> encryptedData)
{
  return EncryptorV3::extractResourceId(encryptedData);
}
}
