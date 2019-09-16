#pragma once

#include <Tanker/EncryptionMetadata.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <gsl-lite.hpp>

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
  static EncryptionMetadata encrypt(std::uint8_t* encryptedData,
                                    gsl::span<std::uint8_t const> clearData,
                                    Trustchain::ResourceId const& resourceId,
                                    Crypto::SymmetricKey const& key);
  static void decrypt(std::uint8_t* decryptedData,
                      Crypto::SymmetricKey const& key,
                      gsl::span<std::uint8_t const> encryptedData);
  static Trustchain::ResourceId extractResourceId(
      gsl::span<std::uint8_t const> encryptedData);
};
}
