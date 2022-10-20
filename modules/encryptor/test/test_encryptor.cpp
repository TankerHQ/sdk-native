#include <Tanker/Crypto/AeadIv.hpp>
#include <Tanker/Crypto/Mac.hpp>
#include <Tanker/Crypto/Padding.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include "test_vectors.hpp"

#include <range/v3/view/iota.hpp>
#include <range/v3/view/zip.hpp>

#include <catch2/catch.hpp>

using namespace Tanker;
using namespace Tanker::Errors;
using Crypto::CompositeResourceId;
using Crypto::ResourceId;
using Crypto::SimpleResourceId;

namespace
{
static constexpr auto oneMiB = 1024 * 1024;

template <typename T>
std::vector<uint8_t> doDecrypt(Crypto::SymmetricKey const& key,
                               gsl::span<uint8_t const> encryptedData)
{
  std::vector<uint8_t> decryptedData(T::decryptedSize(encryptedData));
  auto const decryptedSize = AWAIT(
      T::decrypt(decryptedData, Encryptor::fixedKeyFinder(key), encryptedData));
  decryptedData.resize(decryptedSize);
  return decryptedData;
}

template <typename T>
void testEncryptDecrypt(TestContext<T> ctx,
                        std::string const& testTitle,
                        std::vector<uint8_t> const& clearData)
{
  DYNAMIC_SECTION(testTitle)
  {
    std::vector<uint8_t> encryptedData(ctx.encryptedSize(clearData.size()));
    auto const metadata = AWAIT(ctx.encrypt(encryptedData, clearData));
    auto const decryptedData = doDecrypt<T>(metadata.key, encryptedData);
    CHECK(clearData == decryptedData);
  }
}
}

template <typename T>
void unpaddedEncryptorTests(TestContext<T> ctx)
{
  SECTION("decryptedSize and encryptedSize should be symmetrical")
  {
    std::vector<uint8_t> buf(ctx.encryptedSize(0));
    buf[0] = T::version();
    // This helps stream tests, and is irrelevant for other encryptors
    Serialization::serialize<uint32_t>(
        buf.data() + 1, Streams::Header::defaultEncryptedChunkSize);
    CHECK(T::decryptedSize(buf) == 0);
    buf.resize(ctx.encryptedSize(42));
    CHECK(T::decryptedSize(buf) == 42);
    buf.resize(T::encryptedSize(4 * oneMiB));
    CHECK(T::decryptedSize(buf) == 4 * oneMiB);
  }

  SECTION("extractResourceId should throw on a truncated buffer")
  {
    std::vector<uint8_t> buf(1);
    buf[0] = T::version();

    TANKER_CHECK_THROWS_WITH_CODE(T::extractResourceId(buf),
                                  Errc::InvalidArgument);
  }
}

template <typename T>
void commonEncryptorTests(TestContext<T> ctx)
{
  SECTION("decryptedSize should throw if the buffer is truncated")
  {
    std::vector<std::uint8_t> const truncatedBuffer(1, T::version());
    TANKER_CHECK_THROWS_WITH_CODE(T::decryptedSize(truncatedBuffer),
                                  Errc::InvalidArgument);
  }

  SECTION("encrypt/decrypt should work with all buffer sizes")
  {
    auto const buffers = {{},
                          {0x80},
                          make_buffer("small"),
                          make_buffer("this is the data to encrypt")};

    auto const names = {"empty", "one char", "small", "medium"};

    for (auto const& [buffer, name] : ranges::views::zip(buffers, names))
    {
      auto const title =
          fmt::format("encrypt/decrypt should work with a {} buffer", name);

      testEncryptDecrypt(ctx, title, buffer);
    }
  }

  for (auto const& [i, testVector] :
       ranges::views::zip(ranges::views::iota(0), ctx.testVectors))
  {
    DYNAMIC_SECTION(fmt::format("decrypt should work with test vector #{}", i))
    {
      auto const decryptedData =
          doDecrypt<T>(testVector.key, testVector.encryptedData);

      CHECK(T::extractResourceId(testVector.encryptedData) ==
            testVector.resourceId);
      CHECK(decryptedData == testVector.clearData);
    }
  }

  SECTION("encrypt should never give the same result twice")
  {
    auto const clearData = make_buffer("this is the data to encrypt");
    std::vector<uint8_t> encryptedData1(ctx.encryptedSize(clearData.size()));
    AWAIT(ctx.encrypt(encryptedData1, clearData));
    std::vector<uint8_t> encryptedData2(ctx.encryptedSize(clearData.size()));
    AWAIT(ctx.encrypt(encryptedData2, clearData));

    CHECK(encryptedData1 != encryptedData2);
  }

  for (auto const& [i, testVector] :
       ranges::views::zip(ranges::views::iota(0), ctx.testVectors))
  {
    DYNAMIC_SECTION(
        fmt::format("decrypt should not work with corrupted buffer #{}", i))
    {
      // These tests try to corrupt buffers at arbitrary positions

      // On EncryptorV4, this changes the resource ID, which is not MAC-ed, so
      // it doesn't fail
      if constexpr (!std::is_same_v<T, EncryptorV4>)
      {
        SECTION("corrupt begin")
        {
          testVector.encryptedData[7]++;
        }
      }

      SECTION("corrupt middle")
      {
        // The MAC (present in all formats) takes 16 bytes at the end, so this
        // falls 4 bytes before that.
        testVector.encryptedData[testVector.encryptedData.size() - 20]++;
      }

      SECTION("corrupt end")
      {
        testVector.encryptedData.back()++;
      }

      TANKER_CHECK_THROWS_WITH_CODE(
          doDecrypt<T>(testVector.key, testVector.encryptedData),
          Errc::DecryptionFailed);
    }
  }

  SECTION("extractResourceId should give the same result as encrypt")
  {
    auto const clearData = make_buffer("this is the data to encrypt");
    std::vector<uint8_t> encryptedData(ctx.encryptedSize(clearData.size()));

    auto const metadata = AWAIT(ctx.encrypt(encryptedData, clearData));

    using ResIdType = std::result_of_t<decltype (&T::extractResourceId)(
        gsl::span<std::uint8_t const>)>;
    if constexpr (std::is_same_v<ResIdType, SimpleResourceId>)
      CHECK(T::extractResourceId(encryptedData) == metadata.resourceId);
    else if constexpr (std::is_same_v<ResIdType, CompositeResourceId>)
      // The encrypt metadata's resourceId is the one we want to save in store,
      // for composite resourceIds that's always the sessionId
      CHECK(T::extractResourceId(encryptedData).sessionId() ==
            metadata.resourceId);
    else
      static_assert(!sizeof(ResIdType), "Unexpected resource ID type");
  }
}

template <typename T>
void paddedEncryptorTests(TestContext<T> ctx)
{
  for (auto paddingStep : {1, 2, 5, 13})
  {
    auto const title = fmt::format("With a paddingStep of {}", paddingStep);

    DYNAMIC_SECTION(title.c_str())
    {
      ctx.paddingStep = paddingStep;
      commonEncryptorTests(ctx);
    }
  }

  SECTION("encryptedSize should have a minimal value")
  {
    constexpr auto minimalPadding = Padding::minimalPadding();
    ctx.paddingStep = std::nullopt;
    for (auto clearSize : {0, 1, 8, 9})
      CHECK(ctx.encryptedSize(clearSize) == minimalPadding + ctx.overhead);
  }

  SECTION("encryptedSize should use the padme algorithm in auto padding")
  {
    std::vector<std::pair<int, int>> const paddedWithAuto = {
        {10, 10},
        {11, 12},
        {42, 44},
        {250, 256},
    };
    ctx.paddingStep = std::nullopt;
    for (auto [clearSize, paddedSize] : paddedWithAuto)
      CHECK(ctx.encryptedSize(clearSize) == paddedSize + ctx.overhead);
  }

  SECTION("encryptedSize should use the paddingStep parameter correctly")
  {
    std::vector<std::pair<int, int>> const paddedToStepFive = {
        {0, 5},
        {2, 5},
        {4, 5},
        {5, 5},
        {9, 10},
        {10, 10},
        {14, 15},
        {40, 40},
        {42, 45},
        {45, 45},
    };
    ctx.paddingStep = 5;
    for (auto [clearSize, paddedSize] : paddedToStepFive)
      CHECK(ctx.encryptedSize(clearSize) == paddedSize + ctx.overhead);
  }
}

TEST_CASE("EncryptorV2 tests")
{
  TestContext<EncryptorV2> ctx;

  unpaddedEncryptorTests(ctx);
  commonEncryptorTests(ctx);

  SECTION("encryptedSize should return the right size")
  {
    auto const versionSize = 1;
    constexpr auto MacSize = SimpleResourceId::arraySize;
    constexpr auto IvSize = Crypto::AeadIv::arraySize;
    CHECK(EncryptorV2::encryptedSize(0) == versionSize + 0 + MacSize + IvSize);
    CHECK(EncryptorV2::encryptedSize(1) == versionSize + 1 + MacSize + IvSize);
  }
}

TEST_CASE("EncryptorV3 tests")
{
  TestContext<EncryptorV3> ctx;

  unpaddedEncryptorTests(ctx);
  commonEncryptorTests(ctx);

  SECTION("encryptedSize should return the right size")
  {
    auto const versionSize = 1;
    constexpr auto MacSize = SimpleResourceId::arraySize;
    CHECK(EncryptorV3::encryptedSize(0) == versionSize + 0 + MacSize);
    CHECK(EncryptorV3::encryptedSize(1) == versionSize + 1 + MacSize);
  }

  SECTION("when the last chunk is missing")
  {
    // This data takes a bit more than one chunk
    std::vector<uint8_t> clearData(oneMiB);
    Crypto::randomFill(clearData);

    std::vector<uint8_t> encryptedData(
        EncryptorV4::encryptedSize(clearData.size()));

    auto const metadata = AWAIT(EncryptorV4::encrypt(encryptedData, clearData));

    // Only take the first chunk
    std::vector<uint8_t> truncatedData(encryptedData.begin(),
                                       encryptedData.begin() + oneMiB);

    SECTION("decryptedSize throws")
    {
      TANKER_CHECK_THROWS_WITH_CODE(EncryptorV4::decryptedSize(truncatedData),
                                    Errc::InvalidArgument);
    }

    SECTION("decrypt throws")
    {
      // decryptedSize throws on the truncatedData, so do it on encryptedData
      // just to allocate enough room
      std::vector<uint8_t> decryptedData(
          EncryptorV4::decryptedSize(encryptedData));

      TANKER_CHECK_THROWS_WITH_CODE(AWAIT_VOID(EncryptorV4::decrypt(
                                        decryptedData,
                                        Encryptor::fixedKeyFinder(metadata.key),
                                        truncatedData)),
                                    Errc::DecryptionFailed);
    }
  }
}

TEST_CASE("EncryptorV4 tests")
{
  TestContext<EncryptorV4> ctx;

  commonEncryptorTests(ctx);

  SECTION("encryptedSize should return the right size")
  {
    CHECK(EncryptorV4::encryptedSize(0) ==
          Streams::Header::serializedSize + Crypto::Mac::arraySize);
    CHECK(EncryptorV4::encryptedSize(1) ==
          Streams::Header::serializedSize + Crypto::Mac::arraySize + 1);
    auto const bigSize = 2 * Streams::Header::defaultEncryptedChunkSize + 5;
    CHECK(EncryptorV4::encryptedSize(bigSize) ==
          bigSize +
              3 * (Streams::Header::serializedSize + Crypto::Mac::arraySize));
  }
}

TEST_CASE("EncryptorV5 tests")
{
  TestContext<EncryptorV5> ctx;

  unpaddedEncryptorTests(ctx);
  commonEncryptorTests(ctx);

  SECTION("encryptedSize should return the right size")
  {
    auto const versionSize = 1;
    constexpr auto ResourceIdSize = SimpleResourceId::arraySize;
    constexpr auto IvSize = Crypto::AeadIv::arraySize;
    constexpr auto MacSize = SimpleResourceId::arraySize;
    CHECK(EncryptorV5::encryptedSize(0) ==
          versionSize + ResourceIdSize + IvSize + 0 + MacSize);
    CHECK(EncryptorV5::encryptedSize(1) ==
          versionSize + ResourceIdSize + IvSize + 1 + MacSize);
  }
}

TEST_CASE("extractResourceId should throw on a truncated buffer")
{
  auto encryptedData = make_buffer("");

  TANKER_CHECK_THROWS_WITH_CODE(Encryptor::extractResourceId(encryptedData),
                                Errc::InvalidArgument);
}

TEST_CASE("EncryptorV6 tests")
{
  TestContext<EncryptorV6> ctx;

  commonEncryptorTests(ctx);
  paddedEncryptorTests(ctx);
}

TEST_CASE("EncryptorV7 tests")
{
  TestContext<EncryptorV7> ctx;

  commonEncryptorTests(ctx);
  paddedEncryptorTests(ctx);
}

TEST_CASE("EncryptorV8 tests")
{
  TestContext<EncryptorV8> ctx;

  commonEncryptorTests(ctx);
  paddedEncryptorTests(ctx);
}

TEST_CASE("EncryptorV9 tests")
{
  TestContext<EncryptorV9> ctx;

  commonEncryptorTests(ctx);
  unpaddedEncryptorTests(ctx);

  SECTION("composite resource ID has expected type")
  {
    auto const& testVector = ctx.testVectors[0];
    CompositeResourceId resourceId =
        EncryptorV9::extractResourceId(testVector.encryptedData);
    CHECK(resourceId.type() == CompositeResourceId::transparentSessionType());
  }

  for (auto const& [i, testVector] :
       ranges::views::zip(ranges::views::iota(0), ctx.testVectors))
  {
    DYNAMIC_SECTION(
        fmt::format("decrypt test vector #{} with the individual resource key "
                    "instead of the session",
                    i))
    {
      auto const& encrypted = testVector.encryptedData;
      auto const resourceId = EncryptorV9::extractResourceId(encrypted);

      // Derive individual resource key manually
      auto constexpr bufLen =
          Crypto::SymmetricKey::arraySize + Crypto::SubkeySeed::arraySize;
      std::array<std::uint8_t, bufLen> hashBuf;
      std::copy(testVector.key.begin(), testVector.key.end(), hashBuf.data());
      std::copy(encrypted.begin() + 1 + SimpleResourceId::arraySize,
                encrypted.begin() + 1 + SimpleResourceId::arraySize +
                    Crypto::SubkeySeed::arraySize,
                hashBuf.data() + Crypto::SymmetricKey::arraySize);
      auto const key = Tanker::Crypto::generichash<Crypto::SymmetricKey>(
          gsl::make_span(hashBuf));
      auto keyFinder = [=](SimpleResourceId const& id)
          -> Encryptor::ResourceKeyFinder::result_type {
        if (id == resourceId.individualResourceId())
          TC_RETURN(key);
        else
          TC_RETURN(std::nullopt); // Pretend we don't have the session key
      };

      std::vector<uint8_t> decrypted(EncryptorV9::decryptedSize(encrypted));
      auto const decryptedSize =
          AWAIT(EncryptorV9::decrypt(decrypted, keyFinder, encrypted));
      decrypted.resize(decryptedSize);

      CHECK(decrypted == testVector.clearData);
    }
  }
}

TEST_CASE("EncryptorV10 tests")
{
  TestContext<EncryptorV10> ctx;

  commonEncryptorTests(ctx);
  paddedEncryptorTests(ctx);

  SECTION("composite resource ID has expected type")
  {
    auto const& testVector = ctx.testVectors[0];
    CompositeResourceId resourceId =
        EncryptorV10::extractResourceId(testVector.encryptedData);
    CHECK(resourceId.type() == CompositeResourceId::transparentSessionType());
  }

  for (auto const& [i, testVector] :
       ranges::views::zip(ranges::views::iota(0), ctx.testVectors))
  {
    DYNAMIC_SECTION(
        fmt::format("decrypt test vector #{} with the individual resource key "
                    "instead of the session",
                    i))
    {
      auto const& encrypted = testVector.encryptedData;
      auto const resourceId = EncryptorV10::extractResourceId(encrypted);

      // Derive individual resource key manually
      auto constexpr bufLen =
          Crypto::SymmetricKey::arraySize + Crypto::SubkeySeed::arraySize;
      std::array<std::uint8_t, bufLen> hashBuf;
      std::copy(testVector.key.begin(), testVector.key.end(), hashBuf.data());
      std::copy(encrypted.begin() + 1 + SimpleResourceId::arraySize,
                encrypted.begin() + 1 + SimpleResourceId::arraySize +
                    Crypto::SubkeySeed::arraySize,
                hashBuf.data() + Crypto::SymmetricKey::arraySize);
      auto const key = Tanker::Crypto::generichash<Crypto::SymmetricKey>(
          gsl::make_span(hashBuf));
      auto keyFinder = [=](SimpleResourceId const& id)
          -> Encryptor::ResourceKeyFinder::result_type {
        if (id == resourceId.individualResourceId())
          TC_RETURN(key);
        else
          TC_RETURN(std::nullopt); // Pretend we don't have the session key
      };

      std::vector<uint8_t> decrypted(EncryptorV10::decryptedSize(encrypted));
      auto const decryptedSize =
          AWAIT(EncryptorV10::decrypt(decrypted, keyFinder, encrypted));
      decrypted.resize(decryptedSize);

      CHECK(decrypted == testVector.clearData);
    }
  }
}
