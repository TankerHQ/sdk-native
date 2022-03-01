#pragma once

#include <Tanker/EncryptionMetadata.hpp>
#include <Tanker/Streams/Header.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <gsl/gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstdint>

namespace Tanker
{
class EncryptorV4
{
public:
  static constexpr std::uint32_t version()
  {
    return 4u;
  }

  static std::uint64_t encryptedSize(
      std::uint64_t clearSize,
      std::uint32_t encryptedChunkSize =
          Streams::Header::defaultEncryptedChunkSize);
  static std::uint64_t decryptedSize(
      gsl::span<std::uint8_t const> encryptedData);

  static tc::cotask<EncryptionMetadata> encrypt(
      gsl::span<std::uint8_t> encryptedData,
      gsl::span<std::uint8_t const> clearData,
      std::uint32_t encryptedChunkSize =
          Streams::Header::defaultEncryptedChunkSize);
  static tc::cotask<EncryptionMetadata> encrypt(
      gsl::span<std::uint8_t> encryptedData,
      gsl::span<std::uint8_t const> clearData,
      Trustchain::ResourceId const& resourceId,
      Crypto::SymmetricKey const& key,
      std::uint32_t encryptedChunkSize =
          Streams::Header::defaultEncryptedChunkSize);
  static tc::cotask<std::uint64_t> decrypt(
      gsl::span<std::uint8_t> decryptedData,
      Crypto::SymmetricKey const& key,
      gsl::span<std::uint8_t const> encryptedData);
  static Trustchain::ResourceId extractResourceId(
      gsl::span<std::uint8_t const> encryptedData);
};
}
