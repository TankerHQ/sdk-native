#include <Tanker/AsyncCore.hpp>
#include <Tanker/ChunkEncryptor.hpp>
#include <Tanker/Test/Functional/Trustchain.hpp>

#include "TrustchainFixture.hpp"

#include <Helpers/Buffers.hpp>

#include <doctest.h>

namespace Tanker
{
TEST_CASE_FIXTURE(TrustchainFixture,
                  "ChunkEncryptor" * doctest::test_suite("Functional"))
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  SUBCASE("Can Create and use a chunkEncryptor")
  {
    auto chunkEncryptor = TC_AWAIT(aliceSession->makeChunkEncryptor());
    auto const clearChunk = make_buffer("Chunk 1");
    std::vector<uint8_t> encryptedChunk(
        AsyncCore::encryptedSize(clearChunk.size()));

    chunkEncryptor->encrypt(encryptedChunk, clearChunk, 1);
    chunkEncryptor->encrypt(encryptedChunk, clearChunk, 4);

    std::vector<uint8_t> encryptedSeal(chunkEncryptor->sealSize());
    CHECK_NOTHROW(
        TC_AWAIT(chunkEncryptor->seal(encryptedSeal, {alice.suserId()}, {})));
  }

  SUBCASE("Alice can recreate her chunkEncryptor")
  {
    auto chunkEncryptor = TC_AWAIT(aliceSession->makeChunkEncryptor());
    auto const clearChunk = make_buffer("Chunk 1");
    std::vector<uint8_t> encryptedChunk(
        AsyncCore::encryptedSize(clearChunk.size()));

    chunkEncryptor->encrypt(encryptedChunk, clearChunk, 1);
    chunkEncryptor->encrypt(encryptedChunk, clearChunk, 4);

    std::vector<uint8_t> encryptedSeal(chunkEncryptor->sealSize());
    TC_AWAIT(chunkEncryptor->seal(encryptedSeal, {alice.suserId()}, {}));
    auto newChunkEncryptor =
        TC_AWAIT(aliceSession->makeChunkEncryptor(encryptedSeal));

    CHECK(chunkEncryptor->size() == newChunkEncryptor->size());
    CHECK(chunkEncryptor->sealSize() == newChunkEncryptor->sealSize());
  }

  SUBCASE("Bob can recreate Alice's chunkEncryptor")
  {
    auto bob = trustchain.makeUser();
    auto bobDevice = bob.makeDevice();
    auto bobSession = TC_AWAIT(bobDevice.open());
    TC_AWAIT(aliceSession->syncTrustchain());

    auto chunkEncryptor = TC_AWAIT(aliceSession->makeChunkEncryptor());
    auto const clearChunk = make_buffer("Chunk 1");
    std::vector<uint8_t> encryptedChunk(
        AsyncCore::encryptedSize(clearChunk.size()));

    chunkEncryptor->encrypt(encryptedChunk, clearChunk, 1);
    chunkEncryptor->encrypt(encryptedChunk, clearChunk, 4);

    std::vector<uint8_t> encryptedSeal(chunkEncryptor->sealSize());
    TC_AWAIT(chunkEncryptor->seal(encryptedSeal, {bob.suserId()}, {}));
    auto newChunkEncryptor =
        TC_AWAIT(bobSession->makeChunkEncryptor(encryptedSeal));

    CHECK(chunkEncryptor->size() == newChunkEncryptor->size());
    CHECK(chunkEncryptor->sealSize() == newChunkEncryptor->sealSize());
  }
}
}
