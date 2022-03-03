#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Streams/DecryptionStream.hpp>
#include <Tanker/Streams/EncryptionStream.hpp>
#include <Tanker/Streams/Helpers.hpp>
#include <Tanker/Streams/PeekableInputSource.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

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

Crypto::SymmetricKey const key(std::vector<std::uint8_t>{
    0xa,  0x7,  0x3d, 0xd0, 0x2c, 0x2d, 0x17, 0xf9, 0x49, 0xd9, 0x35,
    0x8e, 0xf7, 0xfe, 0x7b, 0xd1, 0xf6, 0xb,  0xf1, 0x5c, 0xa4, 0x32,
    0x1e, 0xe4, 0xaa, 0x18, 0xe1, 0x97, 0xbf, 0xf4, 0x5e, 0xfe});

tc::cotask<std::int64_t> failRead(gsl::span<std::uint8_t>)
{
  throw Exception(make_error_code(Errc::IOError), "failRead");
}

auto makeKeyFinder(Trustchain::ResourceId const& resourceId,
                   Crypto::SymmetricKey const& key)
{
  return [=](Trustchain::ResourceId const& id)
             -> tc::cotask<Crypto::SymmetricKey> {
    CHECK(id == resourceId);
    TC_RETURN(key);
  };
}

template <typename T>
auto makeKeyFinder(T const& encryptor)
{
  return makeKeyFinder(encryptor.resourceId(), encryptor.symmetricKey());
}

tc::cotask<Crypto::SymmetricKey> mockKeyFinder(Trustchain::ResourceId const& id)
{
  TC_RETURN(key);
}
}

TEST_CASE("Throws when underlying read fails", "[streamencryption]")
{
  EncryptionStream encryptor(failRead);

  auto const mockKeyFinder = [](auto) -> tc::cotask<Crypto::SymmetricKey> {
    TC_RETURN(Crypto::SymmetricKey());
  };

  TANKER_CHECK_THROWS_WITH_CODE(AWAIT(encryptor({})), Errc::IOError);
  TANKER_CHECK_THROWS_WITH_CODE(
      AWAIT(DecryptionStream::create(failRead, mockKeyFinder)), Errc::IOError);
}

TEST_CASE("Encrypt/decrypt huge buffer", "[streamencryption]")
{
  std::vector<std::uint8_t> buffer(
      24 + 5 * Streams::Header::defaultEncryptedChunkSize);
  Crypto::randomFill(buffer);

  EncryptionStream encryptor(bufferViewToInputSource(buffer));

  auto decryptor =
      AWAIT(DecryptionStream::create(encryptor, makeKeyFinder(encryptor)));

  auto const decrypted = AWAIT(readAllStream(decryptor));

  CHECK(decrypted.size() == buffer.size());
  CHECK(decrypted == buffer);
}

TEST_CASE(
    "Performs an underlying read when reading 0 when no buffered output is "
    "left",
    "[streamencryption]")
{
  std::vector<std::uint8_t> buffer(2 *
                                   Streams::Header::defaultEncryptedChunkSize);
  Crypto::randomFill(buffer);
  auto readCallback = bufferViewToInputSource(buffer);
  auto timesCallbackCalled = 0;

  EncryptionStream encryptor(
      [&timesCallbackCalled, cb = std::move(readCallback)](
          gsl::span<std::uint8_t> out) mutable -> tc::cotask<std::int64_t> {
        ++timesCallbackCalled;
        TC_RETURN(TC_AWAIT(cb(out)));
      });

  std::vector<std::uint8_t> encryptedBuffer(
      Streams::Header::defaultEncryptedChunkSize);

  AWAIT(encryptor(gsl::make_span(encryptedBuffer)
                      .subspan(0, Streams::Header::defaultEncryptedChunkSize)));
  CHECK(timesCallbackCalled == 1);
  AWAIT(encryptor({}));
  CHECK(timesCallbackCalled == 2);
  // returns immediately
  AWAIT(encryptor({}));
  CHECK(timesCallbackCalled == 2);
  AWAIT(encryptor(gsl::make_span(encryptedBuffer)
                      .subspan(0, Streams::Header::defaultEncryptedChunkSize)));
  CHECK(timesCallbackCalled == 2);
}

TEST_CASE("Decrypt test vector", "[streamencryption]")
{
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

  auto decryptor = AWAIT(DecryptionStream::create(
      bufferViewToInputSource(encryptedTestVector), mockKeyFinder));

  auto const decrypted = AWAIT(readAllStream(decryptor));

  CHECK(decrypted == clearData);
}

TEST_CASE("Corrupted buffer", "[streamencryption]")
{
  std::vector<std::uint8_t> buffer(16);
  Crypto::randomFill(buffer);

  EncryptionStream encryptor(bufferViewToInputSource(buffer), smallChunkSize);
  auto const encrypted = AWAIT(readAllStream(encryptor));
  auto corrupted = encrypted;
  // corrupt the end of the first chunk
  corrupted.erase(corrupted.begin() + smallChunkSize - 1);

  TANKER_CHECK_THROWS_WITH_CODE(
      AWAIT(DecryptionStream::create(bufferViewToInputSource(corrupted),
                                     makeKeyFinder(encryptor))),
      Errors::Errc::DecryptionFailed);
}

TEST_CASE("Different headers between chunks", "[streamencryption]")
{
  constexpr auto smallChunkSize = 0x46;

  std::vector<std::uint8_t> buffer(16);
  Crypto::randomFill(buffer);

  EncryptionStream encryptor(bufferViewToInputSource(buffer), smallChunkSize);
  auto const encrypted = AWAIT(readAllStream(encryptor));
  auto corrupted = encrypted;
  // change the resource id in the second header
  --corrupted[smallChunkSize + 1 + 4];

  auto decryptor = AWAIT(DecryptionStream::create(
      bufferViewToInputSource(corrupted), makeKeyFinder(encryptor)));

  TANKER_CHECK_THROWS_WITH_CODE(AWAIT(readAllStream(decryptor)),
                                Errors::Errc::DecryptionFailed);
}

TEST_CASE("Wrong chunk order", "[streamencryption]")
{
  constexpr auto smallChunkSize = 0x46;

  // Takes exactly 2 chunks + 1 empty chunk
  std::vector<std::uint8_t> buffer(18);
  Crypto::randomFill(buffer);

  EncryptionStream encryptor(bufferViewToInputSource(buffer), smallChunkSize);
  auto const encrypted = AWAIT(readAllStream(encryptor));
  auto corrupted = encrypted;
  // Swap the first two chunks
  std::rotate(corrupted.begin(),
              corrupted.begin() + smallChunkSize,
              corrupted.begin() + 2 * smallChunkSize);

  TANKER_CHECK_THROWS_WITH_CODE(
      AWAIT(DecryptionStream::create(bufferViewToInputSource(corrupted),
                                     makeKeyFinder(encryptor))),
      Errors::Errc::DecryptionFailed);
}

TEST_CASE("Invalid encryptedChunkSize", "[streamencryption]")
{
  constexpr auto smallChunkSize = 0x46;

  std::vector<std::uint8_t> buffer(16);
  Crypto::randomFill(buffer);

  EncryptionStream encryptor(bufferViewToInputSource(buffer), smallChunkSize);
  auto const encrypted = AWAIT(readAllStream(encryptor));

  SECTION("with an encryptedChunkSize too small")
  {
    auto invalidSizeTestVector = encrypted;
    // set encryptedChunkSize to 2 in all chunks, less than the strict minimum
    invalidSizeTestVector[1] = 2;
    invalidSizeTestVector[smallChunkSize + 1] = 2;

    TANKER_CHECK_THROWS_WITH_CODE(
        AWAIT(DecryptionStream::create(
            bufferViewToInputSource(invalidSizeTestVector),
            makeKeyFinder(encryptor))),
        Errors::Errc::DecryptionFailed);
  }

  SECTION("with a corrupted encryptedChunkSize")
  {
    auto smallSizeTestVector = encrypted;
    // set encryptedChunkSize to 69, but the chunk is originally of size 70
    smallSizeTestVector[1] = 69;
    smallSizeTestVector[smallChunkSize + 1] = 69;

    TANKER_CHECK_THROWS_WITH_CODE(
        AWAIT(DecryptionStream::create(
            bufferViewToInputSource(smallSizeTestVector),
            makeKeyFinder(encryptor))),
        Errors::Errc::DecryptionFailed);
  }
}
