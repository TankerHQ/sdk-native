#pragma once

#include <Tanker/Crypto/Types.hpp>

#include <gsl-lite.hpp>

#include <cstdint>

namespace Tanker
{
namespace Encryptor
{
struct EncryptionMetadata
{
  Crypto::Mac mac;
  Crypto::SymmetricKey key;
};

uint64_t encryptedSize(uint64_t clearSize);
uint64_t decryptedSize(gsl::span<uint8_t const> encrypteData);
EncryptionMetadata encrypt(uint8_t* encryptedData,
                           gsl::span<uint8_t const> clearData);
void decrypt(uint8_t* decryptedData,
             Crypto::SymmetricKey const& key,
             gsl::span<uint8_t const> encryptedData);
Crypto::Mac extractMac(gsl::span<uint8_t const> encryptedData);
}
}
