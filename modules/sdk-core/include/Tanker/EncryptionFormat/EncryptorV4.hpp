#pragma once

#include <Tanker/EncryptionFormat/EncryptionMetadata.hpp>
#include <Tanker/StreamHeader.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstdint>

namespace Tanker
{
namespace EncryptionFormat
{
namespace EncryptorV4
{
constexpr uint32_t version()
{
  return 4u;
}

uint64_t encryptedSize(
    uint64_t clearSize,
    uint32_t encryptedChunkSize = StreamHeader::defaultEncryptedChunkSize);

uint64_t decryptedSize(gsl::span<uint8_t const> encryptedData);

tc::cotask<EncryptionFormat::EncryptionMetadata> encrypt(
    uint8_t* encryptedData,
    gsl::span<uint8_t const> clearData,
    uint32_t encryptedChunkSize = StreamHeader::defaultEncryptedChunkSize);

tc::cotask<void> decrypt(uint8_t* decryptedData,
                         Crypto::SymmetricKey const& key,
                         gsl::span<uint8_t const> encryptedData);

Trustchain::ResourceId extractResourceId(gsl::span<uint8_t const> encryptedData);
}
}
}
