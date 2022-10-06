#pragma once

#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/EncryptionMetadata.hpp>

#include <cstdint>
#include <gsl/gsl-lite.hpp>
#include <optional>
#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
class EncryptorV7
{
public:
  static constexpr std::uint32_t version()
  {
    return 7u;
  }

  static std::uint64_t encryptedSize(std::uint64_t clearSize,
                                     std::optional<std::uint32_t> paddingStep);
  static std::uint64_t decryptedSize(
      gsl::span<std::uint8_t const> encryptedData);
  static tc::cotask<EncryptionMetadata> encrypt(
      gsl::span<std::uint8_t> encryptedData,
      gsl::span<std::uint8_t const> clearData,
      Crypto::SimpleResourceId const& resourceId,
      Crypto::SymmetricKey const& key,
      std::optional<std::uint32_t> paddingStep);
  static tc::cotask<std::uint64_t> decrypt(
      gsl::span<uint8_t> decryptedData,
      Crypto::SymmetricKey const& symmetricKey,
      gsl::span<std::uint8_t const> encryptedData);
  static Crypto::SimpleResourceId extractResourceId(
      gsl::span<std::uint8_t const> encryptedData);
};
}
