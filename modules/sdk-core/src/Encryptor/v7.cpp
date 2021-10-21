#include "Tanker/Encryptor/Padding.hpp"

#include <Tanker/Encryptor/v5.hpp>
#include <Tanker/Encryptor/v7.hpp>

#include <Tanker/Crypto/Crypto.hpp>
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
auto const versionSize = Serialization::varint_size(EncryptorV7::version());

// version 7 format layout:
// [version, 1B] [resourceid, 16B] [iv, 24B] [[ciphertext, variable] [MAC, 16B]]
void checkEncryptedFormat(gsl::span<std::uint8_t const> encryptedData)
{
  auto const dataVersionResult = Serialization::varint_read(encryptedData);
  auto const overheadSize =
      ResourceId::arraySize + Crypto::AeadIv::arraySize + ResourceId::arraySize;

  assert(dataVersionResult.first == EncryptorV7::version());

  if (dataVersionResult.second.size() < overheadSize)
  {
    throw Errors::formatEx(Errors::Errc::InvalidArgument,
                           "truncated encrypted buffer");
  }
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
  // -1 is the padding byte (0x80)
  return EncryptorV5::decryptedSize(encryptedData) - 1ULL;
}

tc::cotask<EncryptionMetadata> EncryptorV7::encrypt(
    std::uint8_t* encryptedData,
    gsl::span<std::uint8_t const> clearData,
    ResourceId const& resourceId,
    Crypto::SymmetricKey const& key,
    std::optional<std::uint32_t> paddingStep)
{
  Serialization::varint_write(encryptedData, version());
  ranges::copy(resourceId, encryptedData + versionSize);
  auto const iv = encryptedData + versionSize + ResourceId::arraySize;
  gsl::span<std::uint8_t const> associatedData(encryptedData, iv);
  Crypto::randomFill(gsl::make_span(iv, Crypto::AeadIv::arraySize));
  auto const paddedData = Padding::padClearData(clearData, paddingStep);
  Crypto::encryptAead(key,
                      iv,
                      encryptedData + versionSize + ResourceId::arraySize +
                          Crypto::AeadIv::arraySize,
                      paddedData,
                      associatedData);
  TC_RETURN((EncryptionMetadata{resourceId, key}));
}

tc::cotask<std::uint64_t> EncryptorV7::decrypt(
    std::uint8_t* decryptedData,
    Crypto::SymmetricKey const& key,
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  auto const associatedData =
      encryptedData.subspan(0, versionSize + ResourceId::arraySize);
  auto const iv = encryptedData.subspan(versionSize + ResourceId::arraySize);
  auto const data = encryptedData.subspan(versionSize + ResourceId::arraySize +
                                          Crypto::AeadIv::arraySize);

  Crypto::decryptAead(key, iv.data(), decryptedData, data, associatedData);

  auto const paddedSize = EncryptorV5::decryptedSize(encryptedData);
  TC_RETURN(Padding::unpaddedSize(gsl::make_span(decryptedData, paddedSize)));
}

ResourceId EncryptorV7::extractResourceId(
    gsl::span<std::uint8_t const> encryptedData)
{
  return EncryptorV5::extractResourceId(encryptedData);
}
}
