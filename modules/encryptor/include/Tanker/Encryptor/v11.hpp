#pragma once

#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/Crypto/SubkeySeed.hpp>
#include <Tanker/EncryptCacheMetadata.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/Streams/TransparentSessionHeader.hpp>

#include <gsl/gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstdint>

namespace Tanker
{
class EncryptorV11
{
public:
  static constexpr auto versionSize = 1;
  static constexpr auto chunkSizeSize = 4;
  static constexpr auto paddingSizeSize = 4;
  static constexpr auto headerSize =
      versionSize + Crypto::SimpleResourceId::arraySize +
      Crypto::SubkeySeed::arraySize + chunkSizeSize;
  static constexpr auto macDataSize =
      versionSize + Crypto::SimpleResourceId::arraySize +
      Crypto::SubkeySeed::arraySize + chunkSizeSize;
  static constexpr auto chunkOverhead =
      paddingSizeSize + Crypto::Mac::arraySize;

public:
  static constexpr std::uint32_t version()
  {
    return 11u;
  }

  static std::uint64_t encryptedSize(
      std::uint64_t clearSize,
      std::optional<std::uint32_t> paddingStep,
      std::uint32_t encryptedChunkSize =
          Streams::TransparentSessionHeader::defaultEncryptedChunkSize);
  static std::uint64_t decryptedSize(
      gsl::span<std::uint8_t const> encryptedData);

  static std::array<uint8_t, macDataSize> makeMacData(
      Crypto::SimpleResourceId const& sessionId,
      Crypto::SubkeySeed const& subkeySeed,
      std::uint32_t chunkSize);

  static Crypto::SymmetricKey deriveSubkey(
      Crypto::SymmetricKey const& sessionKey,
      Crypto::SubkeySeed const& subkeySeed);

  static tc::cotask<EncryptCacheMetadata> encrypt(
      gsl::span<std::uint8_t> encryptedData,
      gsl::span<std::uint8_t const> clearData,
      Crypto::SimpleResourceId const& sessionId,
      Crypto::SymmetricKey const& sessionKey,
      std::optional<std::uint32_t> paddingStep,
      std::uint32_t encryptedChunkSize =
          Streams::TransparentSessionHeader::defaultEncryptedChunkSize);
  static tc::cotask<EncryptCacheMetadata> encrypt(
      gsl::span<std::uint8_t> encryptedData,
      gsl::span<std::uint8_t const> clearData,
      Crypto::SimpleResourceId const& sessionId,
      Crypto::SymmetricKey const& sessionKey,
      Crypto::SubkeySeed const& subkeySeed,
      std::optional<std::uint32_t> paddingStep,
      std::uint32_t encryptedChunkSize =
          Streams::TransparentSessionHeader::defaultEncryptedChunkSize);
  static tc::cotask<std::uint64_t> decrypt(
      gsl::span<std::uint8_t> decryptedData,
      Encryptor::ResourceKeyFinder const& keyFinder,
      gsl::span<std::uint8_t const> encryptedData);
  static Crypto::CompositeResourceId extractResourceId(
      gsl::span<std::uint8_t const> encryptedData);
};
}
