#include <Tanker/Encryptor/v6.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Encryptor/v3.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Varint.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <algorithm>
#include <cmath>
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

std::uint64_t EncryptorV6::paddedClearSize(std::uint64_t clearSize)
{
  return std::max(padme(clearSize + 1), minimalPadding());
}

std::uint64_t EncryptorV6::encryptedSize(std::uint64_t clearSize)
{
  return versionSize + Crypto::encryptedSize(paddedClearSize(clearSize));
}

std::uint64_t EncryptorV6::decryptedSize(
    gsl::span<std::uint8_t const> encryptedData)
{
  // -1 is the padding byte (0x80)
  return EncryptorV3::decryptedSize(encryptedData) - 1ULL;
}

std::uint64_t EncryptorV6::padme(std::uint64_t clearSize)
{
  if (clearSize <= 1u)
    return 0u;

  auto const e = static_cast<std::uint64_t>(std::floor(std::log2(clearSize)));
  auto const s = static_cast<std::uint64_t>(std::floor(std::log2(e)) + 1u);
  auto const lastBits = e - s;
  auto const bitMask = (1ULL << lastBits) - 1ULL;
  return (clearSize + bitMask) & ~bitMask;
}

std::vector<std::uint8_t> EncryptorV6::padClearData(
    gsl::span<std::uint8_t const> clearData)
{
  std::vector<std::uint8_t> res(clearData.begin(), clearData.end());
  res.push_back(0x80);

  auto const paddedSize = paddedClearSize(clearData.size());
  res.resize(paddedSize, 0x00);

  return res;
}

tc::cotask<EncryptionMetadata> EncryptorV6::encrypt(
    std::uint8_t* encryptedData, gsl::span<std::uint8_t const> clearData)
{
  auto const endOfVersion =
      Serialization::varint_write(encryptedData, version());
  auto const key = Crypto::makeSymmetricKey();
  auto const iv = Crypto::AeadIv{};
  auto const paddedData = padClearData(clearData);
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

  auto const clearPaddedSize = EncryptorV3::decryptedSize(encryptedData);
  TC_RETURN(unpaddedSize(gsl::make_span(decryptedData, clearPaddedSize)));
}

std::uint64_t EncryptorV6::unpaddedSize(
    gsl::span<std::uint8_t const> decryptedData)
{
  auto const it = std::find_if(decryptedData.crbegin(),
                               decryptedData.crend(),
                               [](auto const& c) { return c != 0x00; });

  if (it == decryptedData.crend() || *it != 0x80)
    throw Errors::formatEx(Errors::Errc::DecryptionFailed,
                           "unable to remove padding");

  return std::distance(it + 1, decryptedData.crend());
}

ResourceId EncryptorV6::extractResourceId(
    gsl::span<std::uint8_t const> encryptedData)
{
  return EncryptorV3::extractResourceId(encryptedData);
}
}
