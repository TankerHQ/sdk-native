#pragma once

#include <Tanker/EncryptionMetadata.hpp>
#include <Tanker/StreamHeader.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <gsl-lite.hpp>
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
          StreamHeader::defaultEncryptedChunkSize);

  static std::uint64_t decryptedSize(
      gsl::span<std::uint8_t const> encryptedData);

  static tc::cotask<EncryptionMetadata> encrypt(
      std::uint8_t* encryptedData,
      gsl::span<std::uint8_t const> clearData,
      std::uint32_t encryptedChunkSize =
          StreamHeader::defaultEncryptedChunkSize);

  static tc::cotask<void> decrypt(std::uint8_t* decryptedData,
                                  Crypto::SymmetricKey const& key,
                                  gsl::span<std::uint8_t const> encryptedData);

  static Trustchain::ResourceId extractResourceId(
      gsl::span<std::uint8_t const> encryptedData);
};
}
