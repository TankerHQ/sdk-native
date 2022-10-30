#pragma once

#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/EncryptCacheMetadata.hpp>
#include <Tanker/Encryptor.hpp>

#include <gsl/gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstdint>

namespace Tanker
{
class EncryptorV3
{
public:
  static constexpr std::uint32_t version()
  {
    return 3u;
  }

  static std::uint64_t encryptedSize(std::uint64_t clearSize);
  static std::uint64_t decryptedSize(
      gsl::span<std::uint8_t const> encryptedData);
  static tc::cotask<EncryptCacheMetadata> encrypt(
      gsl::span<std::uint8_t> encryptedData,
      gsl::span<std::uint8_t const> clearData);
  static tc::cotask<std::uint64_t> decrypt(
      gsl::span<std::uint8_t> decryptedData,
      Encryptor::ResourceKeyFinder const& keyFinder,
      gsl::span<std::uint8_t const> encryptedData);
  static Crypto::SimpleResourceId extractResourceId(
      gsl::span<std::uint8_t const> encryptedData);
};
}
