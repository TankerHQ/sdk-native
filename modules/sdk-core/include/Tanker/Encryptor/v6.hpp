#pragma once

#include <Tanker/EncryptionMetadata.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <gsl/gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstdint>
#include <optional>
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
  static std::uint64_t encryptedSize(std::uint64_t clearSize,
                                     std::optional<std::uint32_t> paddingStep);
  static std::uint64_t decryptedSize(
      gsl::span<std::uint8_t const> encryptedData);
  static tc::cotask<EncryptionMetadata> encrypt(
      gsl::span<std::uint8_t> encryptedData,
      gsl::span<std::uint8_t const> clearData,
      std::optional<std::uint32_t> paddingStep);
  static tc::cotask<std::uint64_t> decrypt(
      gsl::span<uint8_t> decryptedData,
      Crypto::SymmetricKey const& key,
      gsl::span<std::uint8_t const> encryptedData);
  static Trustchain::ResourceId extractResourceId(
      gsl::span<std::uint8_t const> encryptedData);
};
}
