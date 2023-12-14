#pragma once

#include <Tanker/Crypto/CompositeResourceId.hpp>
#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/Crypto/SubkeySeed.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/EncryptCacheMetadata.hpp>
#include <Tanker/Encryptor.hpp>

#include <gsl/gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstdint>

namespace Tanker
{
class EncryptorV9
{
public:
  static constexpr std::uint32_t version()
  {
    return 9u;
  }

  static std::uint64_t encryptedSize(std::uint64_t clearSize);
  static std::uint64_t decryptedSize(gsl::span<std::uint8_t const> encryptedData);
  static tc::cotask<EncryptCacheMetadata> encrypt(gsl::span<std::uint8_t> encryptedData,
                                                  gsl::span<std::uint8_t const> clearData,
                                                  Crypto::SimpleResourceId const& sessionId,
                                                  Crypto::SymmetricKey const& sessionKey,
                                                  Crypto::SubkeySeed const& subkeySeed);
  static tc::cotask<std::uint64_t> decrypt(gsl::span<std::uint8_t> decryptedData,
                                           Encryptor::ResourceKeyFinder const& keyFinder,
                                           gsl::span<std::uint8_t const> encryptedData);
  static Crypto::CompositeResourceId extractResourceId(gsl::span<std::uint8_t const> encryptedData);
};
}
