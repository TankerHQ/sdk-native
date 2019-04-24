#pragma once

#include <Tanker/EncryptionFormat/EncryptionMetadata.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <gsl-lite.hpp>

#include <cstdint>

namespace Tanker
{
namespace Encryptor
{
uint64_t encryptedSize(uint64_t clearSize);
uint64_t decryptedSize(gsl::span<uint8_t const> encryptedData);
EncryptionFormat::EncryptionMetadata encrypt(
    uint8_t* encryptedData, gsl::span<uint8_t const> clearData);
void decrypt(uint8_t* decryptedData,
             Crypto::SymmetricKey const& key,
             gsl::span<uint8_t const> encryptedData);
Trustchain::ResourceId extractResourceId(gsl::span<uint8_t const> encryptedData);
}
}
