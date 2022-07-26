#pragma once

#include <Tanker/EncryptionMetadata.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <gsl/gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstdint>
#include <optional>

namespace Tanker
{
namespace Encryptor
{
bool isHugeClearData(uint64_t dataSize);

uint64_t encryptedSize(uint64_t clearSize, std::optional<uint32_t> paddingStep);
uint64_t decryptedSize(gsl::span<uint8_t const> encryptedData);
tc::cotask<EncryptionMetadata> encrypt(gsl::span<uint8_t> encryptedData,
                                       gsl::span<uint8_t const> clearData,
                                       std::optional<uint32_t> paddingStep);
tc::cotask<uint64_t> decrypt(gsl::span<uint8_t> decryptedData,
                             Crypto::SymmetricKey const& key,
                             gsl::span<uint8_t const> encryptedData);
Trustchain::ResourceId extractResourceId(
    gsl::span<uint8_t const> encryptedData);
}
}
