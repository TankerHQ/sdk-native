#pragma once

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Seal.hpp>

#include <gsl-lite.hpp>
#include <optional.hpp>

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace Tanker
{
class ChunkEncryptorImpl
{
public:
  ChunkEncryptorImpl() = default;
  void inflate(gsl::span<uint8_t const> encryptedSeal);
  size_t size() const;
  void encrypt(gsl::span<uint8_t> encryptedChunk,
               gsl::span<uint8_t const> clearChunk,
               uint64_t index);
  void decrypt(gsl::span<uint8_t> decryptedChunk,
               gsl::span<uint8_t const> encryptedChunk,
               uint64_t index) const;
  void remove(gsl::span<uint64_t const> indexes);
  static uint64_t encryptedSize(uint64_t clearChunkSize);
  static uint64_t decryptedSize(gsl::span<uint8_t const> encrypteChunk);

  size_t sealSize() const;
  std::vector<uint8_t> seal() const;

protected:
  Seal _seal;
};
}
