#pragma once

#include <Tanker/EncryptionMetadata.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <gsl/gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstdint>
#include <vector>

namespace Tanker
{
class EncryptorV6
{
public:
  static constexpr std::uint32_t version()
  {
    return 6u;
  }
  static std::uint64_t encryptedSize(std::uint64_t clearSize);
  static std::uint64_t decryptedSize(
      gsl::span<std::uint8_t const> encryptedData);
  static tc::cotask<EncryptionMetadata> encrypt(
      std::uint8_t* encryptedData, gsl::span<std::uint8_t const> clearData);
  static tc::cotask<std::uint64_t> decrypt(
      std::uint8_t* decryptedData,
      Crypto::SymmetricKey const& key,
      gsl::span<std::uint8_t const> encryptedData);
  static Trustchain::ResourceId extractResourceId(
      gsl::span<std::uint8_t const> encryptedData);

  static constexpr std::uint64_t minimalPadding()
  {
    return 10u;
  }

  static std::uint64_t padme(std::uint64_t clearSize);
  static std::uint64_t paddedClearSize(std::uint64_t clearSize);
  static std::vector<std::uint8_t> padClearData(
      gsl::span<std::uint8_t const> clearData);
  static std::uint64_t unpaddedSize(
      gsl::span<std::uint8_t const> decryptedData);
};
}
