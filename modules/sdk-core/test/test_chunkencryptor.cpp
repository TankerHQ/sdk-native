#include <doctest.h>

#include <algorithm>
#include <numeric>
#include <stdexcept>

#include <Tanker/ChunkEncryptorImpl.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Seal.hpp>
#include <Tanker/Serialization/Varint.hpp>
#include <Tanker/Session.hpp>

#include <Helpers/Buffers.hpp>

using namespace Tanker;

TEST_CASE("Empty ChunkEncryptor")
{
  ChunkEncryptorImpl chunkEncryptor;

  SUBCASE("Can be constructed")
  {
    CHECK(chunkEncryptor.size() == 0);
  }

  SUBCASE("Can be sealed")
  {
    CHECK_NOTHROW(chunkEncryptor.seal());
  }

  SUBCASE("Has the right version number")
  {
    auto const result = chunkEncryptor.seal();
    auto res = Serialization::varint_read(result);
    CHECK(res.first == Seal::defaultSealVersion());
  }

  SUBCASE("Has the right empty ranges")
  {
    auto const result = chunkEncryptor.seal();
    auto res = Serialization::varint_read(result);
    res = Serialization::varint_read(res.second);
    CHECK(res.first == 0);
  }

  SUBCASE("sealSize is right")
  {
    auto const result = chunkEncryptor.seal();
    auto const sealSize = chunkEncryptor.sealSize();
    CHECK(result.size() == sealSize);
  }

  SUBCASE("Sealed twice yields the same seal")
  {
    auto const seal1 = chunkEncryptor.seal();
    auto const seal2 = chunkEncryptor.seal();
    CHECK(std::equal(seal1.begin(), seal1.end(), seal2.begin()));
  }
}

TEST_CASE("EncryptAt as append")
{
  ChunkEncryptorImpl chunkEncryptor;
  auto const clearChunk = make_buffer("Chunk 1");
  std::vector<uint8_t> encryptedChunk(
      ChunkEncryptor::encryptedSize(clearChunk.size()));

  SUBCASE("Size of chunks is right")
  {
    chunkEncryptor.encrypt(encryptedChunk, clearChunk, 0);
    CHECK(chunkEncryptor.size() == 1);
  }

  SUBCASE("Can append something empty")
  {
    auto const chunk = make_buffer("");
    CHECK_NOTHROW(chunkEncryptor.encrypt(encryptedChunk, chunk, 0));
    CHECK(chunkEncryptor.size() == 1);
  }

  SUBCASE("sealSize is right")
  {
    chunkEncryptor.encrypt(encryptedChunk, clearChunk, 0);
    auto const result = chunkEncryptor.seal();
    auto const sealSize = chunkEncryptor.sealSize();
    CHECK(result.size() == sealSize);
  }

  SUBCASE("Has the right empty ranges")
  {
    chunkEncryptor.encrypt(encryptedChunk, clearChunk, 0);
    auto const sealContent = chunkEncryptor.seal();

    auto seal = Seal::inflate(sealContent);
    auto const emptyRanges = seal.emptyRanges();
    CHECK(emptyRanges.size() == 0);
  }

  SUBCASE("Has a key that looks like a key")
  {
    chunkEncryptor.encrypt(encryptedChunk, clearChunk, 0);
    auto const sealContent = chunkEncryptor.seal();
    auto seal = Seal::inflate(sealContent);
    auto const keys = seal.keys();
    CHECK(keys.size() == 1);
  }
}

TEST_CASE("EncryptAt as replace")
{
  ChunkEncryptorImpl chunkEncryptor;
  auto const clearChunk1 = make_buffer("Chunk 1");
  auto const clearChunk2 = make_buffer("Chunk 2");
  std::vector<uint8_t> encryptedChunk1(
      ChunkEncryptor::encryptedSize(clearChunk1.size()));
  chunkEncryptor.encrypt(encryptedChunk1, clearChunk1, chunkEncryptor.size());

  SUBCASE("Size of chunks is right")
  {
    chunkEncryptor.encrypt(encryptedChunk1, clearChunk2, 0);
    CHECK(chunkEncryptor.size() == 1);
  }

  SUBCASE("sealSize is right")
  {
    chunkEncryptor.encrypt(encryptedChunk1, clearChunk1, 0);
    auto const result = chunkEncryptor.seal();
    auto const sealSize = chunkEncryptor.sealSize();
    CHECK(result.size() == sealSize);
  }

  SUBCASE("Has the right empty ranges")
  {
    chunkEncryptor.encrypt(encryptedChunk1, clearChunk1, 0);
    auto const sealContent = chunkEncryptor.seal();
    auto seal = Seal::inflate(sealContent);
    auto const emptyRanges = seal.emptyRanges();
    CHECK(emptyRanges.size() == 0);
  }

  SUBCASE("Has a key that looks like a key")
  {
    chunkEncryptor.encrypt(encryptedChunk1, clearChunk1, 0);
    auto const sealContent = chunkEncryptor.seal();
    auto seal = Seal::inflate(sealContent);
    auto const keys = seal.keys();
    CHECK(seal.keys().size() == 1);
  }

  SUBCASE("Key has changed")
  {
    auto sealContent = chunkEncryptor.seal();
    auto seal = Seal::inflate(sealContent);
    auto const keys1 = seal.keys();
    chunkEncryptor.encrypt(encryptedChunk1, clearChunk1, 0);
    sealContent = chunkEncryptor.seal();
    auto seal2 = Seal::inflate(sealContent);
    auto const keys2 = seal2.keys();
    CHECK_FALSE(keys1[0] == keys2[0]);
  }
}

TEST_CASE("EncryptAt with 1 hole")
{
  ChunkEncryptorImpl chunkEncryptor;

  auto const clearChunk = make_buffer("Chunk 1");
  std::vector<uint8_t> encryptedChunk(
      ChunkEncryptor::encryptedSize(clearChunk.size()));

  chunkEncryptor.encrypt(encryptedChunk, clearChunk, 1);

  SUBCASE("Size of chunks is right")
  {
    CHECK(chunkEncryptor.size() == 2);
  }

  SUBCASE("sealSize is right")
  {
    auto const result = chunkEncryptor.seal();
    auto const sealSize = chunkEncryptor.sealSize();
    CHECK(result.size() == sealSize);
  }

  SUBCASE("Has the right empty ranges size")
  {
    auto const sealContent = chunkEncryptor.seal();
    auto seal = Seal::inflate(sealContent);
    auto const emptyRanges = seal.emptyRanges();
    // The empty range should be the pair (0-0)
    CHECK(emptyRanges.size() == 1);
  }

  SUBCASE("Has the right empty ranges")
  {
    auto const sealContent = chunkEncryptor.seal();
    auto seal = Seal::inflate(sealContent);
    auto const emptyRanges = seal.emptyRanges();
    CHECK(emptyRanges[0] == Seal::Range(0, 0));
  }

  SUBCASE("Has a key that looks like a key")
  {
    auto const sealContent = chunkEncryptor.seal();
    auto seal = Seal::inflate(sealContent);
    auto const keys = seal.emptyRanges();
    CHECK(keys.size() == 1);
  }
}

TEST_CASE("EncryptAt with multiple holes")
{
  ChunkEncryptorImpl chunkEncryptor;

  auto const clearChunk = make_buffer("Chunk 1");
  std::vector<uint8_t> encryptedChunk(
      ChunkEncryptor::encryptedSize(clearChunk.size()));

  chunkEncryptor.encrypt(encryptedChunk, clearChunk, 1);
  chunkEncryptor.encrypt(encryptedChunk, clearChunk, 4);

  SUBCASE("Size of chunks is right")
  {
    CHECK(chunkEncryptor.size() == 5);
  }

  SUBCASE("sealSize is right")
  {
    auto const result = chunkEncryptor.seal();
    auto const sealSize = chunkEncryptor.sealSize();
    CHECK(result.size() == sealSize);
  }

  SUBCASE("Has the right empty ranges size")
  {
    auto const sealContent = chunkEncryptor.seal();
    auto seal = Seal::inflate(sealContent);
    // The empty range should be the pairs (0-0) (2-3)
    CHECK(seal.emptyRanges().size() == 2);
  }

  SUBCASE("Has the right empty ranges")
  {
    auto const sealContent = chunkEncryptor.seal();
    auto seal = Seal::inflate(sealContent);
    // The empty range should be the pairs (0-0) (2-3)
    auto const emptyRanges = seal.emptyRanges();
    CHECK(emptyRanges[0] == Seal::Range(0, 0));
    CHECK(emptyRanges[1] == Seal::Range(2, 3));
  }

  SUBCASE("Has two valid keys")
  {
    auto const sealContent = chunkEncryptor.seal();
    auto seal = Seal::inflate(sealContent);
    auto const keys = seal.emptyRanges();
    CHECK(keys.size() == 2);
  }
}

TEST_CASE("EncryptAt shorten an empty range")
{
  ChunkEncryptorImpl chunkEncryptor;

  auto const clearChunk = make_buffer("Chunk 1");
  std::vector<uint8_t> encryptedChunk(
      ChunkEncryptor::encryptedSize(clearChunk.size()));

  chunkEncryptor.encrypt(encryptedChunk, clearChunk, 0);
  chunkEncryptor.encrypt(encryptedChunk, clearChunk, 3);
  chunkEncryptor.encrypt(encryptedChunk, clearChunk, 1);

  SUBCASE("sealSize is right")
  {
    auto const result = chunkEncryptor.seal();
    auto const sealSize = chunkEncryptor.sealSize();
    CHECK(result.size() == sealSize);
  }

  SUBCASE("Has the right empty ranges size")
  {
    auto const sealContent = chunkEncryptor.seal();
    auto seal = Seal::inflate(sealContent);
    auto const emptyRanges = seal.emptyRanges();
    // The empty range should be the pairs (0-0) (2-3)
    CHECK(emptyRanges.size() == 1);
  }

  SUBCASE("Has the right empty ranges")
  {
    auto const sealContent = chunkEncryptor.seal();
    auto seal = Seal::inflate(sealContent);
    auto const emptyRanges = seal.emptyRanges();
    CHECK(emptyRanges[0] == Seal::Range(2, 2));
  }

  SUBCASE("Has two valid keys")
  {
    auto const sealContent = chunkEncryptor.seal();
    auto seal = Seal::inflate(sealContent);
    auto const keys = seal.keys();
    CHECK(keys.size() == 3);
  }
}

TEST_CASE("ChunkEncryptor remove")
{
  ChunkEncryptorImpl chunkEncryptor;

  auto const clearChunk = make_buffer("Chunk 1");
  std::vector<uint8_t> encryptedChunk(
      ChunkEncryptor::encryptedSize(clearChunk.size()));

  SUBCASE("Remove throws if remove at bad indexes")
  {
    chunkEncryptor.encrypt(encryptedChunk, clearChunk, chunkEncryptor.size());
    std::vector<uint64_t> indexes = {1};
    CHECK_THROWS_AS(chunkEncryptor.remove(indexes),
                    Error::ChunkIndexOutOfRange);
  }

  SUBCASE("Remove throws if remove on empty ChunkEncryptor")
  {
    std::vector<uint64_t> indexes = {0};
    CHECK_THROWS_AS(chunkEncryptor.remove(indexes),
                    Error::ChunkIndexOutOfRange);
  }

  SUBCASE("Remove simple")
  {
    std::vector<uint64_t> indexes = {0};
    chunkEncryptor.encrypt(encryptedChunk, clearChunk, chunkEncryptor.size());
    chunkEncryptor.remove(indexes);

    SUBCASE("size is right")
    {
      CHECK(chunkEncryptor.size() == 0);
    }

    SUBCASE("sealSize is right after remove simple")
    {
      auto const result = chunkEncryptor.seal();
      auto const sealSize = chunkEncryptor.sealSize();
      CHECK(result.size() == sealSize);
    }
  }

  SUBCASE("Remove works with multiple similar indexes")
  {
    std::vector<uint64_t> indexes = {0, 0};
    chunkEncryptor.encrypt(encryptedChunk, clearChunk, chunkEncryptor.size());
    chunkEncryptor.encrypt(encryptedChunk, clearChunk, chunkEncryptor.size());
    CHECK_NOTHROW(chunkEncryptor.remove(indexes));
    CHECK(chunkEncryptor.size() == 1);
  }

  SUBCASE("Remove Multiple")
  {
    std::vector<std::vector<uint8_t>> encryptedChunks(10);
    auto const encryptedSize = ChunkEncryptor::encryptedSize(clearChunk.size());
    for (auto& encryptedChunk : encryptedChunks)
    {
      encryptedChunk.resize(encryptedSize);
      chunkEncryptor.encrypt(encryptedChunk, clearChunk, chunkEncryptor.size());
    }

    std::vector<uint64_t> indexes = {0, 3, 7, 8};

    SUBCASE("Size is right")
    {
      chunkEncryptor.remove(indexes);

      CHECK(chunkEncryptor.size() == 6);
    }

    SUBCASE("sealSize is right after remove multiple")
    {
      auto const result = chunkEncryptor.seal();
      auto const sealSize = chunkEncryptor.sealSize();
      CHECK(result.size() == sealSize);
    }
  }

  SUBCASE("Remove with empty ranges")
  {
    chunkEncryptor.encrypt(encryptedChunk, clearChunk, 2);
    std::vector<uint64_t> indexes = {1};
    chunkEncryptor.remove(indexes);

    SUBCASE("Size is right")
    {
      CHECK(chunkEncryptor.size() == 2);
    }

    SUBCASE("sealSize is right after remove empty ranges")
    {
      auto const result = chunkEncryptor.seal();
      auto const sealSize = chunkEncryptor.sealSize();
      CHECK(result.size() == sealSize);
    }

    SUBCASE("Has the right empty ranges")
    {
      auto const sealContent = chunkEncryptor.seal();
      auto seal = Seal::inflate(sealContent);
      auto const emptyRanges = seal.emptyRanges();
      CHECK(emptyRanges.size() == 1);
      CHECK(emptyRanges[0] == Seal::Range{0, 0});
    }

    SUBCASE("Can remove an emptyRange")
    {
      std::vector<uint64_t> indexes2 = {0};
      chunkEncryptor.remove(indexes2);
      auto const sealContent = chunkEncryptor.seal();
      auto seal = Seal::inflate(sealContent);
      auto const emptyRanges = seal.emptyRanges();
      CHECK(emptyRanges.empty());
    }
  }

  SUBCASE("Can remove holes and chunk")
  {
    chunkEncryptor.encrypt(encryptedChunk, clearChunk, 0);
    chunkEncryptor.encrypt(encryptedChunk, clearChunk, 2);
    chunkEncryptor.encrypt(encryptedChunk, clearChunk, 3);
    std::vector<uint64_t> indexes = {0, 2};
    chunkEncryptor.remove(indexes);
    CHECK(chunkEncryptor.size() == 2);

    std::vector<uint8_t> decryptedChunk(
        ChunkEncryptor::decryptedSize(encryptedChunk));

    chunkEncryptor.decrypt(decryptedChunk, encryptedChunk, 1);
    CHECK(std::equal(
        decryptedChunk.begin(), decryptedChunk.end(), clearChunk.begin()));
  }
}

TEST_CASE("ChunkEncryptor decrypt")
{
  ChunkEncryptorImpl chunkEncryptor;

  auto const clearChunk = make_buffer("Chunk 1");
  std::vector<uint8_t> encryptedChunk(
      ChunkEncryptor::encryptedSize(clearChunk.size()));

  SUBCASE("Decrypt bad index")
  {
    chunkEncryptor.encrypt(encryptedChunk, clearChunk, chunkEncryptor.size());
    std::vector<uint8_t> decryptedChunk(
        ChunkEncryptor::decryptedSize(encryptedChunk));
    // The Chunk is not inserted
    CHECK_THROWS_AS(chunkEncryptor.decrypt(decryptedChunk, encryptedChunk, 1),
                    Error::ChunkIndexOutOfRange);
  }

  SUBCASE("Decrypt good index")
  {
    chunkEncryptor.encrypt(encryptedChunk, clearChunk, chunkEncryptor.size());
    std::vector<uint8_t> decryptedChunk(
        ChunkEncryptor::decryptedSize(encryptedChunk));
    CHECK_NOTHROW(chunkEncryptor.decrypt(decryptedChunk, encryptedChunk, 0));
    CHECK(decryptedChunk == clearChunk);
  }

  SUBCASE("Decrypt with empty key")
  {
    chunkEncryptor.encrypt(encryptedChunk, clearChunk, 4);
    std::vector<uint8_t> decryptedChunk(
        ChunkEncryptor::decryptedSize(encryptedChunk));
    CHECK_THROWS_AS(chunkEncryptor.decrypt(decryptedChunk, encryptedChunk, 2),
                    Error::ChunkNotFound);
  }

  SUBCASE("Can decrypt multiple after a remove")
  {
    std::vector<std::vector<uint8_t>> encryptedChunks(10);
    auto const encryptedSize = ChunkEncryptor::encryptedSize(clearChunk.size());
    for (auto& encryptedChunk : encryptedChunks)
    {
      encryptedChunk.resize(encryptedSize);
      chunkEncryptor.encrypt(encryptedChunk, clearChunk, chunkEncryptor.size());
    }

    std::vector<uint64_t> indexes = {0, 3, 7, 8};

    chunkEncryptor.remove(indexes);

    std::vector<uint8_t> clear(clearChunk.size());
    CHECK_NOTHROW(chunkEncryptor.decrypt(clear, encryptedChunks[1], 0));
    CHECK_NOTHROW(chunkEncryptor.decrypt(clear, encryptedChunks[2], 1));
    CHECK_NOTHROW(chunkEncryptor.decrypt(clear, encryptedChunks[4], 2));
    CHECK_NOTHROW(chunkEncryptor.decrypt(clear, encryptedChunks[5], 3));
    CHECK_NOTHROW(chunkEncryptor.decrypt(clear, encryptedChunks[6], 4));
    CHECK_NOTHROW(chunkEncryptor.decrypt(clear, encryptedChunks[9], 5));
  }

  SUBCASE("Can decrypt a test vector")
  {
    auto plaintext = "L'enfer, c'est l'implem' des autres";
    auto encryptedChunkVector = std::vector<uint8_t>(
        {0xf2, 0xf2, 0x8b, 0xad, 0x3f, 0x41, 0x25, 0x38, 0x74, 0xa3, 0xfe,
         0x7e, 0x26, 0xce, 0xcb, 0xd5, 0xdf, 0xc2, 0xf2, 0xff, 0xb4, 0xa9,
         0x36, 0x7c, 0x6c, 0x8f, 0x03, 0x64, 0xc6, 0x11, 0x65, 0x40, 0x77,
         0xd5, 0x92, 0xbe, 0xb2, 0xf9, 0x1d, 0xba, 0x4b, 0xd2, 0x69, 0x1b,
         0x72, 0xd1, 0x9c, 0x71, 0x30, 0x3b, 0x69, 0x57, 0x7a, 0x6a, 0x1f,
         0x76, 0x7a, 0xa8, 0x1c, 0x6e, 0xe3, 0x99, 0x24, 0x0a, 0x67, 0xdf,
         0xec, 0xb8, 0xb9, 0x94, 0x85, 0x52, 0x43, 0x4c, 0x71});
    auto keyVector = std::vector<uint8_t>(
        {0x12, 0x94, 0x2c, 0x13, 0x58, 0x77, 0xa1, 0x12, 0xd0, 0x58, 0xf3,
         0x5b, 0x4d, 0x44, 0xa5, 0x5d, 0xe8, 0xe6, 0xb9, 0xf9, 0x13, 0x6b,
         0x3a, 0xce, 0x06, 0x44, 0xcf, 0xec, 0xfd, 0xa3, 0x74, 0xe6});
    std::vector<uint8_t> decryptedChunk(
        ChunkEncryptor::decryptedSize(encryptedChunkVector));

    auto testVector = std::vector<uint8_t>({0x03, 0x00});
    testVector.insert(testVector.end(), keyVector.begin(), keyVector.end());
    chunkEncryptor.inflate(testVector);

    chunkEncryptor.decrypt(decryptedChunk, encryptedChunkVector, 0);
    CHECK(std::equal(decryptedChunk.begin(), decryptedChunk.end(), plaintext));
  }
}

TEST_CASE("Inflate")
{
  ChunkEncryptorImpl chunkEncryptor;

  SUBCASE("Throws if version of the seal is not the current one")
  {
    std::vector<uint8_t> const fakeSeal = {1, 2, 0, 4};
    CHECK_THROWS_AS(chunkEncryptor.inflate(fakeSeal),
                    Error::VersionNotSupported);
  }

  SUBCASE("Can inflate a seal and have exactly the same keys")
  {
    auto const clearChunk = make_buffer("Chunk 1");
    std::vector<uint8_t> encryptedChunk(
        ChunkEncryptor::encryptedSize(clearChunk.size()));

    chunkEncryptor.encrypt(encryptedChunk, clearChunk, 3);
    chunkEncryptor.encrypt(encryptedChunk, clearChunk, 4);
    chunkEncryptor.encrypt(encryptedChunk, clearChunk, 9);
    auto const seal = chunkEncryptor.seal();

    ChunkEncryptorImpl inflatedChunk;
    inflatedChunk.inflate(seal);

    CHECK(chunkEncryptor.size() == inflatedChunk.size());
    CHECK(chunkEncryptor.sealSize() == inflatedChunk.sealSize());
  }

  SUBCASE("Can inflate a seal V3 test vector")
  {
    auto header = std::vector<uint8_t>({
        // Version
        0x03,
        // Size of serialized empty ranges varints (size being a varint too!)
        0x04,
        // First empty range
        0x00,
        0x00,
        // Second empty range
        0x03,
        0x04,
    });
    auto key1 = std::vector<uint8_t>(
        {// Key 1
         0x04, 0x96, 0x60, 0xc5, 0xf3, 0x5e, 0xe0, 0x83, 0xd6, 0xfa, 0x08,
         0x8e, 0x8b, 0xb1, 0x5a, 0x96, 0x9e, 0x9c, 0x27, 0xc1, 0x9c, 0x77,
         0xcb, 0x4a, 0xee, 0x6d, 0xf9, 0x11, 0xb8, 0x2f, 0x0e, 0xf3});
    auto key2 = std::vector<uint8_t>(
        {// Key 2
         0x43, 0x5d, 0x42, 0x2d, 0x9a, 0x75, 0x57, 0xf5, 0xe0, 0x41, 0x81,
         0x10, 0x13, 0xe8, 0xba, 0x5b, 0xf2, 0xc3, 0x47, 0xd5, 0xf7, 0x3f,
         0xd5, 0xa2, 0x20, 0x47, 0x1f, 0x04, 0x6a, 0xd6, 0x49, 0xff});
    auto key5 = std::vector<uint8_t>({
        // Key 5
        0xb2, 0x9f, 0x32, 0xc7, 0xe6, 0x8e, 0xfd, 0x12, 0x1a, 0xd7, 0x33,
        0xd2, 0x2f, 0x41, 0xec, 0x30, 0x56, 0x97, 0x3a, 0xa4, 0x1e, 0xae,
        0xa2, 0x71, 0x8f, 0x94, 0x63, 0xf2, 0x8d, 0x64, 0x9c, 0x86,
    });
    auto testVector = header;
    testVector.insert(testVector.end(), key1.begin(), key1.end());
    testVector.insert(testVector.end(), key2.begin(), key2.end());
    testVector.insert(testVector.end(), key5.begin(), key5.end());

    Seal seal = Seal::inflate(testVector);
    CHECK(seal.nbElements() == 6);

    auto const keys = seal.keys();

    CHECK(std::equal(key1.begin(), key1.end(), keys[0].begin()));
    CHECK(std::equal(key2.begin(), key2.end(), keys[1].begin()));
    CHECK(std::equal(key5.begin(), key5.end(), keys[2].begin()));

    auto const ranges = seal.emptyRanges();
    CHECK(ranges.size() == 2);
    CHECK(ranges[0] == Seal::Range(0, 0));
    CHECK(ranges[1] == Seal::Range(3, 4));
  }
}
