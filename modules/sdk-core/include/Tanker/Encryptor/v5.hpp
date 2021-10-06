#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/EncryptionMetadata.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

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
      std::uint8_t* encryptedData,
      gsl::span<std::uint8_t const> clearData,
      Trustchain::ResourceId const& resourceId,
      Crypto::SymmetricKey const& key);
  static tc::cotask<std::uint64_t> decrypt(
      std::uint8_t* decryptedData,
      Crypto::SymmetricKey const& symmetricKey,
      gsl::span<std::uint8_t const> encryptedData);
  static Trustchain::ResourceId extractResourceId(
      gsl::span<std::uint8_t const> encryptedData);
};
}
