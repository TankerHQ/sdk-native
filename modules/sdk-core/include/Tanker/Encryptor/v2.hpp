#pragma once

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/EncryptionMetadata.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <gsl/gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstdint>

namespace Tanker
{
class EncryptorV2
{
public:
  static constexpr std::uint32_t version()
  {
    return 2u;
  }

  static std::uint64_t encryptedSize(std::uint64_t clearSize);
  static std::uint64_t decryptedSize(
      gsl::span<std::uint8_t const> encryptedData);
  // encrypt returns a cotask to implement the Encryptor concept, but it doesn't
  // need to be async, so encryptSync is the synchronous variant
  static EncryptionMetadata encryptSync(uint8_t* encryptedData,
                                        gsl::span<std::uint8_t const> clearData,
                                        Crypto::SymmetricKey const& key);
  static tc::cotask<EncryptionMetadata> encrypt(
      uint8_t* encryptedData, gsl::span<std::uint8_t const> clearData);
  static tc::cotask<std::uint64_t> decrypt(
      std::uint8_t* decryptedData,
      Crypto::SymmetricKey const& key,
      gsl::span<std::uint8_t const> encryptedData);
  static Trustchain::ResourceId extractResourceId(
      gsl::span<std::uint8_t const> encryptedData);
};
}
