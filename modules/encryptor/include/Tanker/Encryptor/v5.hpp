#pragma once

#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/EncryptionMetadata.hpp>
#include <Tanker/Encryptor.hpp>

#include <gsl/gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstdint>

namespace Tanker
{
class EncryptorV5
{
public:
  static constexpr std::uint32_t version()
  {
    return 5u;
  }

  static std::uint64_t encryptedSize(std::uint64_t clearSize);
  static std::uint64_t decryptedSize(
      gsl::span<std::uint8_t const> encryptedData);
  static tc::cotask<EncryptionMetadata> encrypt(
      gsl::span<std::uint8_t> encryptedData,
      gsl::span<std::uint8_t const> clearData,
      Crypto::SimpleResourceId const& resourceId,
      Crypto::SymmetricKey const& key);
  static tc::cotask<std::uint64_t> decrypt(
      gsl::span<std::uint8_t> decryptedData,
      Encryptor::ResourceKeyFinder const& keyFinder,
      gsl::span<std::uint8_t const> encryptedData);
  static Crypto::SimpleResourceId extractResourceId(
      gsl::span<std::uint8_t const> encryptedData);
};
}
