#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Padding.hpp>
#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/Streams/DecryptionStreamV4.hpp>
#include <Tanker/Streams/DecryptionStreamV8.hpp>
#include <Tanker/Streams/EncryptionStreamV4.hpp>
#include <Tanker/Streams/EncryptionStreamV8.hpp>
#include <Tanker/Streams/Helpers.hpp>
#include <Tanker/Streams/PeekableInputSource.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include <catch2/catch.hpp>

#include <algorithm>
#include <cstdint>
#include <vector>

using namespace Tanker;
using namespace Tanker::Errors;
using namespace Tanker::Streams;

namespace
{
constexpr auto smallChunkSize = 0x46;

tc::cotask<std::int64_t> failRead(gsl::span<std::uint8_t>)
{
  throw Exception(make_error_code(Errc::IOError), "failRead");
}

auto makeKeyFinder(Crypto::SimpleResourceId const& resourceId,
                   Crypto::SymmetricKey const& key)
{
  return [=](Crypto::SimpleResourceId const& id)
             -> tc::cotask<std::optional<Crypto::SymmetricKey>> {
    CHECK(id == resourceId);
    TC_RETURN(key);
  };
}

template <typename T>
auto makeKeyFinder(T const& encryptor)
{
  return makeKeyFinder(encryptor.resourceId(), encryptor.symmetricKey());
}

template <typename DecStream>
std::vector<uint8_t> decryptAllStream(
    InputSource source, typename DecStream::ResourceKeyFinder const& keyFinder)
{
  auto decryptor = AWAIT(DecStream::create(source, keyFinder));

  return AWAIT(readAllStream(decryptor));
}

void swapSecondChunk(std::vector<uint8_t>& a, std::vector<uint8_t>& b)
{
  assert(a.size() == b.size());
  assert(a.size() > 2 * smallChunkSize);
  assert(a[1] == smallChunkSize);

#if !NDEBUG
  auto const resourceIdA = gsl::make_span(a).subspan(5, 16);
  auto const resourceIdB = gsl::make_span(a).subspan(5, 16);

  assert(resourceIdA == resourceIdB &&
         "for this to work, the buffers must use the same key and resource id");
#endif

  auto const rangeA = gsl::make_span(a).subspan(smallChunkSize, smallChunkSize);
  auto const rangeB = gsl::make_span(b).subspan(smallChunkSize, smallChunkSize);

  std::vector<uint8_t> tmp(smallChunkSize);
  ranges::copy(rangeA, tmp.begin());
  ranges::copy(rangeB, rangeA.begin());
  ranges::copy(tmp, rangeB.begin());
}

template <typename EncStream, typename DecStream>
void commonStreamTests()
{
  SECTION("Throws when underlying read fails")
  {
    EncStream encryptor(failRead);

    auto const mockKeyFinder =
        [](auto) -> tc::cotask<std::optional<Crypto::SymmetricKey>> {
      TC_RETURN(Crypto::SymmetricKey());
    };

    TANKER_CHECK_THROWS_WITH_CODE(AWAIT(encryptor({})), Errc::IOError);
    TANKER_CHECK_THROWS_WITH_CODE(
        decryptAllStream<DecStream>(failRead, mockKeyFinder), Errc::IOError);
  }

  SECTION("Encrypt/decrypt with small chunks")
  {
    static constexpr auto smallClearChunkSize =
        smallChunkSize - EncStream::overhead;

    auto const bufferSize = GENERATE(
        0,                       // empty buffer
        2,                       // single chunk
        smallClearChunkSize + 2, // one chunk and a half
        2 * smallClearChunkSize, // exactly 2 chunks (and one empty one)
        300                      // lots of chunks
    );
    CAPTURE(bufferSize);

    std::vector<std::uint8_t> buffer(bufferSize);
    Crypto::randomFill(buffer);

    EncStream encryptor(bufferViewToInputSource(buffer), smallChunkSize);

    auto decryptor =
        AWAIT(DecStream::create(encryptor, makeKeyFinder(encryptor)));

    auto const decrypted = AWAIT(readAllStream(decryptor));

    CHECK(decrypted.size() == buffer.size());
    CHECK(decrypted == buffer);
  }

  SECTION("Encrypt/decrypt huge buffer")
  {
    std::vector<std::uint8_t> buffer(
        24 + 5 * Streams::Header::defaultEncryptedChunkSize);
    Crypto::randomFill(buffer);

    EncStream encryptor(bufferViewToInputSource(buffer));

    auto const decrypted =
        decryptAllStream<DecStream>(encryptor, makeKeyFinder(encryptor));

    CHECK(decrypted == buffer);
  }

  SECTION(
      "Performs an underlying read when reading 0 when no buffered output is "
      "left",
      "[streamencryption]")
  {
    std::vector<std::uint8_t> buffer(
        2 * Streams::Header::defaultEncryptedChunkSize);
    Crypto::randomFill(buffer);
    auto readCallback = bufferViewToInputSource(buffer);
    auto timesCallbackCalled = 0;

    EncStream encryptor(
        [&timesCallbackCalled, cb = std::move(readCallback)](
            gsl::span<std::uint8_t> out) mutable -> tc::cotask<std::int64_t> {
          ++timesCallbackCalled;
          TC_RETURN(TC_AWAIT(cb(out)));
        });

    std::vector<std::uint8_t> encryptedBuffer(
        Streams::Header::defaultEncryptedChunkSize);

    AWAIT(
        encryptor(gsl::make_span(encryptedBuffer)
                      .subspan(0, Streams::Header::defaultEncryptedChunkSize)));
    CHECK(timesCallbackCalled == 1);
    AWAIT(encryptor({}));
    CHECK(timesCallbackCalled == 2);
    // returns immediately
    AWAIT(encryptor({}));
    CHECK(timesCallbackCalled == 2);
    AWAIT(
        encryptor(gsl::make_span(encryptedBuffer)
                      .subspan(0, Streams::Header::defaultEncryptedChunkSize)));
    CHECK(timesCallbackCalled == 2);
  }

  SECTION("Corrupted buffer")
  {
    std::vector<std::uint8_t> buffer(32);
    Crypto::randomFill(buffer);

    EncStream encryptor(bufferViewToInputSource(buffer), smallChunkSize);
    auto const encrypted = AWAIT(readAllStream(encryptor));
    auto corrupted = encrypted;
    // corrupt the end of the first chunk
    corrupted.erase(corrupted.begin() + smallChunkSize - 1);

    TANKER_CHECK_THROWS_WITH_CODE(
        decryptAllStream<DecStream>(bufferViewToInputSource(corrupted),
                                    makeKeyFinder(encryptor)),
        Errors::Errc::DecryptionFailed);
  }

  SECTION("Different headers between chunks")
  {
    constexpr auto smallChunkSize = 0x46;

    std::vector<std::uint8_t> buffer(32);
    Crypto::randomFill(buffer);

    EncStream encryptor(bufferViewToInputSource(buffer), smallChunkSize);
    auto const encrypted = AWAIT(readAllStream(encryptor));
    auto corrupted = encrypted;
    // change the resource id in the second header
    --corrupted[smallChunkSize + 1 + 4];

    TANKER_CHECK_THROWS_WITH_CODE(
        decryptAllStream<DecStream>(bufferViewToInputSource(corrupted),
                                    makeKeyFinder(encryptor)),
        Errors::Errc::DecryptionFailed);
  }

  SECTION("Wrong chunk order")
  {
    constexpr auto smallChunkSize = 0x46;
    constexpr auto plainChunkSize = smallChunkSize - EncStream::overhead;

    // Takes exactly 2 chunks + 1 empty chunk
    std::vector<std::uint8_t> buffer(plainChunkSize * 2);
    Crypto::randomFill(buffer);

    EncStream encryptor(bufferViewToInputSource(buffer), smallChunkSize);
    auto const encrypted = AWAIT(readAllStream(encryptor));
    auto corrupted = encrypted;
    // Swap the first two chunks
    std::rotate(corrupted.begin(),
                corrupted.begin() + smallChunkSize,
                corrupted.begin() + 2 * smallChunkSize);

    TANKER_CHECK_THROWS_WITH_CODE(
        decryptAllStream<DecStream>(bufferViewToInputSource(corrupted),
                                    makeKeyFinder(encryptor)),
        Errors::Errc::DecryptionFailed);
  }
}

// Tests that specifically touch the v4/v8 serialized header
template <typename EncStream, typename DecStream>
void v4v8CommonStreamTests()
{
  SECTION("Invalid encryptedChunkSize")
  {
    constexpr auto smallChunkSize = 0x46;

    std::vector<std::uint8_t> buffer(32);
    Crypto::randomFill(buffer);

    EncStream encryptor(bufferViewToInputSource(buffer), smallChunkSize);
    auto const encrypted = AWAIT(readAllStream(encryptor));

    SECTION("with an encryptedChunkSize too small")
    {
      auto invalidSizeTestVector = encrypted;
      // set encryptedChunkSize to 2 in all chunks, less than the strict minimum
      invalidSizeTestVector[1] = 2;
      invalidSizeTestVector[smallChunkSize + 1] = 2;

      TANKER_CHECK_THROWS_WITH_CODE(
          decryptAllStream<DecStream>(
              bufferViewToInputSource(invalidSizeTestVector),
              makeKeyFinder(encryptor)),
          Errors::Errc::DecryptionFailed);
    }

    SECTION("with a corrupted encryptedChunkSize")
    {
      auto smallSizeTestVector = encrypted;
      // set encryptedChunkSize to 69, but the chunk is originally of size 70
      smallSizeTestVector[1] = 69;
      smallSizeTestVector[smallChunkSize + 1] = 69;

      TANKER_CHECK_THROWS_WITH_CODE(
          decryptAllStream<DecStream>(
              bufferViewToInputSource(smallSizeTestVector),
              makeKeyFinder(encryptor)),
          Errors::Errc::DecryptionFailed);
    }
  }

  // Make sure our test helper works
  SECTION("swapSecondChunk")
  {
    auto const smallClearChunkSize = smallChunkSize - EncStream::overhead;

    std::vector<std::uint8_t> buffer1(2 * smallClearChunkSize, 0x11);
    std::vector<std::uint8_t> buffer2(2 * smallClearChunkSize, 0x22);

    auto const resourceId = Crypto::getRandom<Crypto::SimpleResourceId>();
    auto const key = Crypto::makeSymmetricKey();

    EncStream encryptor1(
        bufferViewToInputSource(buffer1), resourceId, key, smallChunkSize);
    EncStream encryptor2(
        bufferViewToInputSource(buffer2), resourceId, key, smallChunkSize);

    auto encrypted1 = AWAIT(readAllStream(encryptor1));
    auto encrypted2 = AWAIT(readAllStream(encryptor2));

    swapSecondChunk(encrypted1, encrypted2);

    auto decryptor1 = AWAIT(DecStream::create(
        bufferViewToInputSource(encrypted1), makeKeyFinder(encryptor1)));
    auto decryptor2 = AWAIT(DecStream::create(
        bufferViewToInputSource(encrypted2), makeKeyFinder(encryptor2)));

    auto const decrypted1 = AWAIT(readAllStream(decryptor1));
    auto const decrypted2 = AWAIT(readAllStream(decryptor2));

    CHECK(gsl::make_span(decrypted1).subspan(0, smallClearChunkSize) ==
          gsl::make_span(buffer1).subspan(0, smallClearChunkSize));
    CHECK(gsl::make_span(decrypted1).subspan(smallClearChunkSize) ==
          gsl::make_span(buffer2).subspan(smallClearChunkSize));

    CHECK(gsl::make_span(decrypted2).subspan(0, smallClearChunkSize) ==
          gsl::make_span(buffer2).subspan(0, smallClearChunkSize));
    CHECK(gsl::make_span(decrypted2).subspan(smallClearChunkSize) ==
          gsl::make_span(buffer1).subspan(smallClearChunkSize));
  }
}
}

TEST_CASE("Stream V4", "[streamencryption]")
{
  commonStreamTests<EncryptionStreamV4, DecryptionStreamV4>();
  v4v8CommonStreamTests<EncryptionStreamV4, DecryptionStreamV4>();

  SECTION("Decrypt test vector")
  {
    Crypto::SimpleResourceId resourceId(std::vector<uint8_t>{0x40,
                                                             0xec,
                                                             0x8d,
                                                             0x84,
                                                             0xad,
                                                             0xbe,
                                                             0x2b,
                                                             0x27,
                                                             0x32,
                                                             0xc9,
                                                             0xa,
                                                             0x1e,
                                                             0xc6,
                                                             0x8f,
                                                             0x2b,
                                                             0xdb});
    Crypto::SymmetricKey const key(std::vector<std::uint8_t>{
        0xa,  0x7,  0x3d, 0xd0, 0x2c, 0x2d, 0x17, 0xf9, 0x49, 0xd9, 0x35,
        0x8e, 0xf7, 0xfe, 0x7b, 0xd1, 0xf6, 0xb,  0xf1, 0x5c, 0xa4, 0x32,
        0x1e, 0xe4, 0xaa, 0x18, 0xe1, 0x97, 0xbf, 0xf4, 0x5e, 0xfe});

    auto clearData = make_buffer("this is a secret");

    auto encryptedTestVector = std::vector<uint8_t>(
        {0x4,  0x46, 0x0,  0x0,  0x0,  0x40, 0xec, 0x8d, 0x84, 0xad, 0xbe, 0x2b,
         0x27, 0x32, 0xc9, 0xa,  0x1e, 0xc6, 0x8f, 0x2b, 0xdb, 0xcd, 0x7,  0xd0,
         0x3a, 0xc8, 0x74, 0xe1, 0x8,  0x7e, 0x5e, 0xaa, 0xa2, 0x82, 0xd8, 0x8b,
         0xf5, 0xed, 0x22, 0xe6, 0x30, 0xbb, 0xaa, 0x9d, 0x71, 0xe3, 0x9a, 0x4,
         0x22, 0x67, 0x3d, 0xdf, 0xcf, 0x28, 0x48, 0xe2, 0xeb, 0x4b, 0xb4, 0x30,
         0x92, 0x70, 0x23, 0x49, 0x1c, 0xc9, 0x31, 0xcb, 0xda, 0x1a, 0x4,  0x46,
         0x0,  0x0,  0x0,  0x40, 0xec, 0x8d, 0x84, 0xad, 0xbe, 0x2b, 0x27, 0x32,
         0xc9, 0xa,  0x1e, 0xc6, 0x8f, 0x2b, 0xdb, 0x3f, 0x34, 0xf3, 0xd3, 0x23,
         0x90, 0xfc, 0x6,  0x35, 0xda, 0x99, 0x1e, 0x81, 0xdf, 0x88, 0xfc, 0x21,
         0x1e, 0xed, 0x3a, 0x28, 0x2d, 0x51, 0x82, 0x77, 0x7c, 0xf6, 0xbe, 0x54,
         0xd4, 0x92, 0xcd, 0x86, 0xd4, 0x88, 0x55, 0x20, 0x1f, 0xd6, 0x44, 0x47,
         0x30, 0x40, 0x2f, 0xe8, 0xf4, 0x50});

    auto decryptor = AWAIT(
        DecryptionStreamV4::create(bufferViewToInputSource(encryptedTestVector),
                                   makeKeyFinder(resourceId, key)));

    auto const decrypted = AWAIT(readAllStream(decryptor));

    CHECK(decrypted == clearData);
  }
}

namespace
{
struct EncryptionStreamV8NoPad : EncryptionStreamV8
{
  EncryptionStreamV8NoPad(
      InputSource cb,
      std::uint32_t encryptedChunkSize = Header::defaultEncryptedChunkSize)
    : EncryptionStreamV8(cb, Padding::Off, encryptedChunkSize)
  {
  }

  EncryptionStreamV8NoPad(
      InputSource cb,
      Crypto::SimpleResourceId const& resourceId,
      Crypto::SymmetricKey const& key,
      std::uint32_t encryptedChunkSize = Header::defaultEncryptedChunkSize)
    : EncryptionStreamV8(cb, resourceId, key, Padding::Off, encryptedChunkSize)
  {
  }
};
}

TEST_CASE("Stream V8", "[streamencryption]")
{
  commonStreamTests<EncryptionStreamV8NoPad, DecryptionStreamV8>();
  v4v8CommonStreamTests<EncryptionStreamV8NoPad, DecryptionStreamV8>();

  auto const smallClearChunkSize =
      smallChunkSize - EncryptionStreamV8::overhead;

  SECTION("exactly 2 chunks including padding")
  {
    std::vector<std::uint8_t> buffer(15);
    Crypto::randomFill(buffer);

    EncryptionStreamV8 encryptor(
        bufferViewToInputSource(buffer), std::nullopt, smallChunkSize);
    auto encrypted = AWAIT(readAllStream(encryptor));

    CHECK(encrypted.size() ==
          2 * smallChunkSize + EncryptionStreamV8::overhead);

    auto decryptor = AWAIT(DecryptionStreamV8::create(
        bufferViewToInputSource(encrypted), makeKeyFinder(encryptor)));
    auto const decrypted = AWAIT(readAllStream(decryptor));

    CHECK(decrypted == buffer);
  }

  SECTION("exactly 2 chunks excluding padding")
  {
    std::vector<std::uint8_t> buffer(16);
    Crypto::randomFill(buffer);

    auto const paddingSize = 2;

    EncryptionStreamV8 encryptor(bufferViewToInputSource(buffer),
                                 buffer.size() + paddingSize,
                                 smallChunkSize);
    auto encrypted = AWAIT(readAllStream(encryptor));

    CHECK(encrypted.size() ==
          2 * smallChunkSize + paddingSize + EncryptionStreamV8::overhead);

    auto decryptor = AWAIT(DecryptionStreamV8::create(
        bufferViewToInputSource(encrypted), makeKeyFinder(encryptor)));
    auto const decrypted = AWAIT(readAllStream(decryptor));

    CHECK(decrypted == buffer);
  }

  SECTION("multiple chunks of padding")
  {
    std::vector<std::uint8_t> buffer(4);
    Crypto::randomFill(buffer);

    EncryptionStreamV8 encryptor(bufferViewToInputSource(buffer),
                                 3 * smallClearChunkSize - 1,
                                 smallChunkSize);
    auto encrypted = AWAIT(readAllStream(encryptor));

    CHECK(encrypted.size() == 3 * smallChunkSize - 1);

    auto decryptor = AWAIT(DecryptionStreamV8::create(
        bufferViewToInputSource(encrypted), makeKeyFinder(encryptor)));
    auto const decrypted = AWAIT(readAllStream(decryptor));

    CHECK(decrypted == buffer);
  }

  SECTION("multiple chunks of padding ending with empty chunk")
  {
    std::vector<std::uint8_t> buffer(4);
    Crypto::randomFill(buffer);

    EncryptionStreamV8 encryptor(bufferViewToInputSource(buffer),
                                 3 * smallClearChunkSize,
                                 smallChunkSize);
    auto encrypted = AWAIT(readAllStream(encryptor));

    CHECK(encrypted.size() ==
          3 * smallChunkSize + EncryptionStreamV8::overhead);

    auto decryptor = AWAIT(DecryptionStreamV8::create(
        bufferViewToInputSource(encrypted), makeKeyFinder(encryptor)));
    auto const decrypted = AWAIT(readAllStream(decryptor));

    CHECK(decrypted == buffer);
  }

  SECTION("decrypting a trucated padding should fail")
  {
    std::vector<std::uint8_t> buffer(4);
    Crypto::randomFill(buffer);

    EncryptionStreamV8 encryptor(bufferViewToInputSource(buffer),
                                 3 * smallClearChunkSize,
                                 smallChunkSize);
    auto encrypted = AWAIT(readAllStream(encryptor));

    CHECK(encrypted.size() ==
          3 * smallChunkSize + EncryptionStreamV8::overhead);

    SECTION("truncate last chunk")
    {
      encrypted.resize(3 * smallChunkSize);
    }
    SECTION("truncate last two chunk")
    {
      encrypted.resize(2 * smallChunkSize);
    }

    auto decryptor = AWAIT(DecryptionStreamV8::create(
        bufferViewToInputSource(encrypted), makeKeyFinder(encryptor)));
    TANKER_CHECK_THROWS_WITH_CODE(AWAIT(readAllStream(decryptor)),
                                  Errors::Errc::DecryptionFailed);
  }

  SECTION("decrypt forged buffer with padding in middle of data")
  {
    std::vector<std::uint8_t> buffer1(3 * smallClearChunkSize, 0x11);
    std::vector<std::uint8_t> buffer2(1, 0x22);

    auto const resourceId = Crypto::getRandom<Crypto::SimpleResourceId>();
    auto const key = Crypto::makeSymmetricKey();

    EncryptionStreamV8 encryptor1(bufferViewToInputSource(buffer1),
                                  resourceId,
                                  key,
                                  3 * smallClearChunkSize,
                                  smallChunkSize);
    EncryptionStreamV8 encryptor2(bufferViewToInputSource(buffer2),
                                  resourceId,
                                  key,
                                  3 * smallClearChunkSize,
                                  smallChunkSize);

    auto encrypted1 = AWAIT(readAllStream(encryptor1));
    auto encrypted2 = AWAIT(readAllStream(encryptor2));

    // Make sure we got the math right, we should have 3 chunks + 1 empty chunk
    REQUIRE(encrypted1.size() ==
            3 * smallChunkSize + EncryptionStreamV8::overhead);
    REQUIRE(encrypted2.size() ==
            3 * smallChunkSize + EncryptionStreamV8::overhead);

    swapSecondChunk(encrypted1, encrypted2);

    auto decryptor1 = AWAIT(DecryptionStreamV8::create(
        bufferViewToInputSource(encrypted1), makeKeyFinder(encryptor1)));
    auto decryptor2 = AWAIT(DecryptionStreamV8::create(
        bufferViewToInputSource(encrypted2), makeKeyFinder(encryptor2)));

    TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(AWAIT(readAllStream(decryptor1)),
                                              Errors::Errc::DecryptionFailed,
                                              "unable to remove padding");
    TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(AWAIT(readAllStream(decryptor2)),
                                              Errors::Errc::DecryptionFailed,
                                              "unable to remove padding");
  }

  SECTION("Decrypt test vector")
  {
    Crypto::SimpleResourceId resourceId(std::vector<uint8_t>{0x93,
                                                             0x76,
                                                             0x48,
                                                             0xf2,
                                                             0x0b,
                                                             0xe2,
                                                             0x93,
                                                             0x79,
                                                             0x4e,
                                                             0xf6,
                                                             0x05,
                                                             0x9a,
                                                             0x25,
                                                             0xec,
                                                             0xfe,
                                                             0xbf});
    Crypto::SymmetricKey const key(std::vector<std::uint8_t>{
        0x1e, 0xe4, 0xfc, 0x13, 0x74, 0x10, 0x8d, 0x25, 0x08, 0xc6, 0x03,
        0xe7, 0x8d, 0xf2, 0x2a, 0x11, 0x5f, 0x10, 0xc3, 0x4c, 0x0e, 0x22,
        0xdd, 0x8c, 0xb6, 0x41, 0xc3, 0x83, 0xcb, 0x56, 0x3d, 0xfd});

    auto clearData = make_buffer("this is a secret");

    auto encryptedTestVector = std::vector<uint8_t>(
        {0x08, 0x46, 0x00, 0x00, 0x00, 0x93, 0x76, 0x48, 0xf2, 0x0b, 0xe2, 0x93,
         0x79, 0x4e, 0xf6, 0x05, 0x9a, 0x25, 0xec, 0xfe, 0xbf, 0x64, 0x6b, 0x6e,
         0x20, 0x9c, 0x66, 0xce, 0xbc, 0xbd, 0x24, 0x05, 0x3e, 0x10, 0xc4, 0xb3,
         0x70, 0x92, 0x79, 0x22, 0xc2, 0xcd, 0x1f, 0x03, 0x3b, 0xdd, 0xcf, 0x7d,
         0x07, 0xcb, 0x09, 0x82, 0xc1, 0xc8, 0xd0, 0xda, 0x6f, 0x7a, 0xbf, 0xa7,
         0xda, 0x7d, 0x97, 0xa1, 0xf0, 0x9b, 0x03, 0x1a, 0x81, 0xa5, 0x08, 0x46,
         0x00, 0x00, 0x00, 0x93, 0x76, 0x48, 0xf2, 0x0b, 0xe2, 0x93, 0x79, 0x4e,
         0xf6, 0x05, 0x9a, 0x25, 0xec, 0xfe, 0xbf, 0x2e, 0x9d, 0x78, 0x53, 0x59,
         0x30, 0x9d, 0x73, 0x5a, 0xdb, 0x18, 0x5d, 0xb0, 0x31, 0xf0, 0x1e, 0x28,
         0xbb, 0x05, 0x4c, 0xd2, 0x02, 0xff, 0x43, 0xb1, 0xef, 0x5d, 0xfd, 0xe2,
         0x04, 0x81, 0xa6, 0x1d, 0x58, 0x27, 0x95, 0x77, 0xe2, 0xb5, 0x33, 0x8e,
         0x92, 0x4a, 0x93, 0xb2, 0xce, 0xbf, 0x12, 0x14, 0x08, 0x46, 0x00, 0x00,
         0x00, 0x93, 0x76, 0x48, 0xf2, 0x0b, 0xe2, 0x93, 0x79, 0x4e, 0xf6, 0x05,
         0x9a, 0x25, 0xec, 0xfe, 0xbf, 0x35, 0xd8, 0xcd, 0x57, 0xc1, 0xff, 0xad,
         0x27, 0x10, 0x2a, 0xb5, 0x15, 0x0d, 0x77, 0x3d, 0x63, 0x66, 0xb9, 0x3d,
         0xe8, 0x04, 0x8b, 0xfd, 0x24, 0x2f, 0xc4, 0xc9, 0xab, 0xca, 0x7f, 0x79,
         0xa6, 0x3d, 0xf2, 0xf4, 0xb3, 0x3d, 0x1f, 0xa3, 0xdd, 0x36});

    auto decryptor = AWAIT(
        DecryptionStreamV8::create(bufferViewToInputSource(encryptedTestVector),
                                   makeKeyFinder(resourceId, key)));

    auto const decrypted = AWAIT(readAllStream(decryptor));

    CHECK(decrypted == clearData);
  }
}
