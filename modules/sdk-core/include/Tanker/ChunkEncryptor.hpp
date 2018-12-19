#pragma once

#include <Tanker/ChunkEncryptorImpl.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/Types/SUserId.hpp>

#include <gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace Tanker
{
class Session;

class ChunkEncryptor
{
public:
  ChunkEncryptor(Session* session);

  tc::cotask<void> open(gsl::span<uint8_t const> encryptedSeal);

  tc::cotask<void> seal(gsl::span<uint8_t> encryptedSeal,
                        std::vector<SUserId> const& suserIds,
                        std::vector<SGroupId> const& sgroupIds) const;
  size_t sealSize() const;

  size_t size() const;
  void encrypt(gsl::span<uint8_t> encryptedChunk,
               gsl::span<uint8_t const> clearChunk,
               uint64_t index = std::numeric_limits<uint64_t>::max());
  void decrypt(gsl::span<uint8_t> decryptedChunk,
               gsl::span<uint8_t const> encryptedChunk,
               uint64_t index) const;
  void remove(gsl::span<uint64_t const> indexes);
  static uint64_t encryptedSize(uint64_t clearChunkSize);
  static uint64_t decryptedSize(gsl::span<uint8_t const> encrypteChunk);

private:
  Session* _session;
  ChunkEncryptorImpl _impl;
};
}
