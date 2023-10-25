#pragma once

#include <Tanker/Crypto/ResourceId.hpp>
#include <Tanker/EncryptCacheMetadata.hpp>

#include <gsl/gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstdint>
#include <optional>

namespace Tanker
{
namespace Encryptor
{
using ResourceKeyFinder =
    std::function<tc::cotask<std::optional<Crypto::SymmetricKey>>(
        Crypto::SimpleResourceId const&)>;
inline ResourceKeyFinder fixedKeyFinder(Crypto::SymmetricKey key)
{
  return [key = std::move(key)](Crypto::SimpleResourceId const&)
             -> ResourceKeyFinder::result_type { TC_RETURN(key); };
}

bool isHugeClearData(uint64_t dataSize, std::optional<uint32_t> paddingStep);

uint64_t encryptedSize(uint64_t clearSize, std::optional<uint32_t> paddingStep);
uint64_t decryptedSize(gsl::span<uint8_t const> encryptedData);
tc::cotask<EncryptCacheMetadata> encrypt(
    gsl::span<uint8_t> encryptedData,
    gsl::span<uint8_t const> clearData,
    std::optional<uint32_t> paddingStep,
    Crypto::SimpleResourceId transparentSessionId,
    Crypto::SymmetricKey transparentSessionKey);
tc::cotask<uint64_t> decrypt(gsl::span<uint8_t> decryptedData,
                             ResourceKeyFinder const& keyFinder,
                             gsl::span<uint8_t const> encryptedData);
tc::cotask<uint64_t> decrypt(gsl::span<uint8_t> decryptedData,
                             Crypto::SymmetricKey const& key,
                             gsl::span<uint8_t const> encryptedData);
Crypto::ResourceId extractResourceId(gsl::span<uint8_t const> encryptedData);
}
}
