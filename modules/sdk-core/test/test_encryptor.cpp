#include <Tanker/Crypto/AeadIv.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/Encryptor/v2.hpp>
#include <Tanker/Encryptor/v3.hpp>
#include <Tanker/Encryptor/v4.hpp>
#include <Tanker/Encryptor/v5.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include <range/v3/view/iota.hpp>
#include <range/v3/view/zip.hpp>

#include <catch2/catch.hpp>

using namespace Tanker;
using namespace Tanker::Errors;

namespace
{
static constexpr auto oneMiB = 1024 * 1024;

struct TestVector
{
  Crypto::SymmetricKey key;
  std::vector<uint8_t> clearData;
  std::vector<uint8_t> encryptedData;
  Trustchain::ResourceId resourceId;

  TestVector(std::vector<uint8_t> const& key,
             std::vector<uint8_t> const& clearData,
             std::vector<uint8_t> const& encryptedData,
             std::vector<uint8_t> const& resourceId)
    : key(key),
      clearData(clearData),
      encryptedData(encryptedData),
      resourceId(resourceId)
  {
  }
};

template <typename T>
struct TestContext;

template <>
struct TestContext<EncryptorV2>
{
  tc::cotask<EncryptionMetadata> encrypt(
      gsl::span<std::uint8_t> encryptedData,
      gsl::span<std::uint8_t const> clearData) const
  {
    return EncryptorV2::encrypt(encryptedData, clearData);
  }

  std::vector<TestVector> testVectors{
      {{0x76, 0xd,  0x8e, 0x80, 0x5c, 0xbc, 0xa8, 0xb6, 0xda, 0xea, 0xcf,
        0x66, 0x46, 0xca, 0xd7, 0xeb, 0x4f, 0x3a, 0xbc, 0x69, 0xac, 0x9b,
        0xce, 0x77, 0x35, 0x8e, 0xa8, 0x31, 0xd7, 0x2f, 0x14, 0xdd},
       make_buffer("this is very secret"),
       {0x02, 0x32, 0x93, 0xa3, 0xf8, 0x6c, 0xa8, 0x82, 0x25, 0xbc, 0x17, 0x7e,
        0xb5, 0x65, 0x9b, 0xee, 0xd,  0xfd, 0xcf, 0xc6, 0x5c, 0x6d, 0xb4, 0x72,
        0xe0, 0x5b, 0x33, 0x27, 0x4c, 0x83, 0x84, 0xd1, 0xad, 0xda, 0x5f, 0x86,
        0x2,  0x46, 0x42, 0x91, 0x71, 0x30, 0x65, 0x2e, 0x72, 0x47, 0xe6, 0x48,
        0x20, 0xa1, 0x86, 0x91, 0x7f, 0x9c, 0xb5, 0x5e, 0x91, 0xb3, 0x65, 0x2d},
       {0x72,
        0x47,
        0xe6,
        0x48,
        0x20,
        0xa1,
        0x86,
        0x91,
        0x7f,
        0x9c,
        0xb5,
        0x5e,
        0x91,
        0xb3,
        0x65,
        0x2d}},
  };
};

template <>
struct TestContext<EncryptorV3>
{
  tc::cotask<EncryptionMetadata> encrypt(
      gsl::span<std::uint8_t> encryptedData,
      gsl::span<std::uint8_t const> clearData) const
  {
    return EncryptorV3::encrypt(encryptedData, clearData);
  }

  std::vector<TestVector> testVectors{
      {{0x76, 0xd,  0x8e, 0x80, 0x5c, 0xbc, 0xa8, 0xb6, 0xda, 0xea, 0xcf,
        0x66, 0x46, 0xca, 0xd7, 0xeb, 0x4f, 0x3a, 0xbc, 0x69, 0xac, 0x9b,
        0xce, 0x77, 0x35, 0x8e, 0xa8, 0x31, 0xd7, 0x2f, 0x14, 0xdd},
       make_buffer("this is very secret"),
       {0x03, 0x37, 0xb5, 0x3d, 0x55, 0x34, 0xb5, 0xc1, 0x3f, 0xe3, 0x72, 0x81,
        0x47, 0xf0, 0xca, 0xda, 0x29, 0x99, 0x6e, 0x4,  0xa8, 0x41, 0x81, 0xa0,
        0xe0, 0x5e, 0x8e, 0x3a, 0x8,  0xd3, 0x78, 0xfa, 0x5,  0x9f, 0x17, 0xfa},
       {0xa8,
        0x41,
        0x81,
        0xa0,
        0xe0,
        0x5e,
        0x8e,
        0x3a,
        0x8,
        0xd3,
        0x78,
        0xfa,
        0x5,
        0x9f,
        0x17,
        0xfa}},
  };
};

template <>
struct TestContext<EncryptorV4>
{
  tc::cotask<EncryptionMetadata> encrypt(
      gsl::span<std::uint8_t> encryptedData,
      gsl::span<std::uint8_t const> clearData) const
  {
    return EncryptorV4::encrypt(encryptedData, clearData);
  }

  std::vector<TestVector> testVectors{
      // Empty buffer
      {{0xda, 0xa5, 0x3d, 0x7,  0xc,  0x4b, 0x63, 0x54, 0xe3, 0x6f, 0x96,
        0xc1, 0x14, 0x4c, 0x23, 0xcc, 0x16, 0x23, 0x52, 0xa1, 0xc5, 0x53,
        0xe3, 0xea, 0xd9, 0xc4, 0x1d, 0x28, 0x4c, 0x45, 0x43, 0xa9},
       {},
       {0x4,  0x0,  0x0,  0x10, 0x0,  0x5e, 0x44, 0x54, 0xa7, 0x83, 0x21,
        0xd8, 0x77, 0x8c, 0x7a, 0x25, 0xc9, 0x46, 0x52, 0xa,  0x60, 0x1d,
        0xb1, 0x25, 0xaf, 0x1e, 0x85, 0x84, 0xa9, 0xcf, 0x19, 0x71, 0x26,
        0x79, 0xf3, 0x47, 0xd1, 0xf6, 0xf0, 0xf7, 0x2,  0x85, 0x47, 0xfb,
        0xe8, 0x5e, 0x16, 0x25, 0x33, 0xf6, 0x66, 0x7b, 0xb9, 0xd5, 0xa5,
        0x1d, 0xe9, 0x23, 0x71, 0xb,  0x75},
       {0x5e,
        0x44,
        0x54,
        0xa7,
        0x83,
        0x21,
        0xd8,
        0x77,
        0x8c,
        0x7a,
        0x25,
        0xc9,
        0x46,
        0x52,
        0xa,
        0x60}},
      // Buffer with default chunk size
      {{0xaf, 0x38, 0x67, 0x9d, 0x20, 0x56, 0x38, 0x6b, 0xef, 0xdd, 0x62,
        0x6d, 0x60, 0x1b, 0xf9, 0x39, 0xad, 0x71, 0x43, 0xc0, 0x30, 0x14,
        0xed, 0xea, 0x56, 0xff, 0x1f, 0x8a, 0x30, 0x90, 0xb6, 0x8b},
       make_buffer("this is a secret"),
       {0x4,  0x0,  0x0,  0x10, 0x0,  0xf2, 0x38, 0x50, 0x31, 0x6c, 0xfa,
        0xaa, 0x96, 0x8c, 0x1b, 0x25, 0x43, 0xf4, 0x38, 0xe3, 0x61, 0x55,
        0x24, 0x50, 0xe8, 0x3b, 0x3,  0xe9, 0xf6, 0x1,  0xf1, 0x73, 0x5f,
        0x3e, 0x52, 0xb2, 0x8f, 0xc0, 0x1f, 0xd,  0xcd, 0xac, 0x8f, 0x5,
        0x2a, 0xbd, 0x31, 0x32, 0xe,  0x16, 0xdd, 0x20, 0x40, 0x58, 0xa2,
        0xfe, 0xc6, 0xf3, 0x5d, 0xff, 0x25, 0xe8, 0xc9, 0x33, 0xc1, 0x8,
        0xe0, 0xb1, 0xb0, 0xb,  0xe4, 0x86, 0x8c, 0x36, 0xb8, 0x2f, 0xbf},
       {0xf2,
        0x38,
        0x50,
        0x31,
        0x6c,
        0xfa,
        0xaa,
        0x96,
        0x8c,
        0x1b,
        0x25,
        0x43,
        0xf4,
        0x38,
        0xe3,
        0x61}},
      // Buffer with very small chunk size
      {{0xa,  0x7,  0x3d, 0xd0, 0x2c, 0x2d, 0x17, 0xf9, 0x49, 0xd9, 0x35,
        0x8e, 0xf7, 0xfe, 0x7b, 0xd1, 0xf6, 0xb,  0xf1, 0x5c, 0xa4, 0x32,
        0x1e, 0xe4, 0xaa, 0x18, 0xe1, 0x97, 0xbf, 0xf4, 0x5e, 0xfe},
       make_buffer("this is a secret"),
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
        0x30, 0x40, 0x2f, 0xe8, 0xf4, 0x50},
       {0x40,
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
        0xdb}},
  };
};

template <>
struct TestContext<EncryptorV5>
{
  tc::cotask<EncryptionMetadata> encrypt(
      gsl::span<std::uint8_t> encryptedData,
      gsl::span<std::uint8_t const> clearData) const
  {
    return EncryptorV5::encrypt(encryptedData,
                                clearData,
                                Crypto::getRandom<Trustchain::ResourceId>(),
                                Crypto::makeSymmetricKey());
  }

  std::vector<TestVector> testVectors{
      {{0x76, 0xd,  0x8e, 0x80, 0x5c, 0xbc, 0xa8, 0xb6, 0xda, 0xea, 0xcf,
        0x66, 0x46, 0xca, 0xd7, 0xeb, 0x4f, 0x3a, 0xbc, 0x69, 0xac, 0x9b,
        0xce, 0x77, 0x35, 0x8e, 0xa8, 0x31, 0xd7, 0x2f, 0x14, 0xdd},
       make_buffer("this is very secret"),
       {0x05, 0xc1, 0x74, 0x53, 0x1e, 0xdd, 0x77, 0x77, 0x87, 0x2c, 0x02,
        0x6e, 0xf2, 0x36, 0xdf, 0x28, 0x7e, 0x70, 0xea, 0xb6, 0xe7, 0x72,
        0x7d, 0xdd, 0x42, 0x5d, 0xa1, 0xab, 0xb3, 0x6e, 0xd1, 0x8b, 0xea,
        0xd7, 0xf5, 0xad, 0x23, 0xc0, 0xbd, 0x8c, 0x1f, 0x68, 0xc7, 0x9e,
        0xf2, 0xe9, 0xd8, 0x9e, 0xf9, 0x7e, 0x93, 0xc4, 0x29, 0x0d, 0x96,
        0x40, 0x2d, 0xbc, 0xf8, 0x0b, 0xb8, 0x4f, 0xfc, 0x48, 0x9b, 0x83,
        0xd1, 0x05, 0x51, 0x40, 0xfc, 0xc2, 0x7f, 0x6e, 0xd9, 0x16},
       {0xc1,
        0x74,
        0x53,
        0x1e,
        0xdd,
        0x77,
        0x77,
        0x87,
        0x2c,
        0x02,
        0x6e,
        0xf2,
        0x36,
        0xdf,
        0x28,
        0x7e}},
  };
};

template <typename T>
std::vector<uint8_t> doDecrypt(Crypto::SymmetricKey const& key,
                               gsl::span<uint8_t const> encryptedData)
{
  std::vector<uint8_t> decryptedData(T::decryptedSize(encryptedData));
  AWAIT_VOID(T::decrypt(decryptedData, key, encryptedData));
  return decryptedData;
}

template <typename T>
void testEncryptDecrypt(TestContext<T> ctx,
                        std::string const& testTitle,
                        std::vector<uint8_t> const& clearData)
{
  DYNAMIC_SECTION(testTitle)
  {
    std::vector<uint8_t> encryptedData(T::encryptedSize(clearData.size()));
    auto const metadata = AWAIT(ctx.encrypt(encryptedData, clearData));
    auto const decryptedData = doDecrypt<T>(metadata.key, encryptedData);
    CHECK(clearData == decryptedData);
  }
}
}

template <typename T>
void commonEncryptorTests(TestContext<T> ctx)
{
  SECTION("decryptedSize and encryptedSize should be symmetrical")
  {
    std::vector<uint8_t> buf(T::encryptedSize(0));
    buf[0] = T::version();
    // This helps stream tests, and is irrelevant for other encryptors
    Serialization::serialize<uint32_t>(
        buf.data() + 1, Streams::Header::defaultEncryptedChunkSize);
    CHECK(T::decryptedSize(buf) == 0);
    buf.resize(T::encryptedSize(42));
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

  SECTION("extractResourceId should throw on a truncated buffer")
  {
    std::vector<uint8_t> buf(1);
    Serialization::varint_write(buf.data(), T::version());

    TANKER_CHECK_THROWS_WITH_CODE(T::extractResourceId(buf),
                                  Errc::InvalidArgument);
  }

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
    auto clearData = make_buffer("this is the data to encrypt");
    std::vector<uint8_t> encryptedData1(T::encryptedSize(clearData.size()));
    AWAIT(ctx.encrypt(encryptedData1, clearData));
    std::vector<uint8_t> encryptedData2(T::encryptedSize(clearData.size()));
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
    auto clearData = make_buffer("this is the data to encrypt");
    std::vector<uint8_t> encryptedData(T::encryptedSize(clearData.size()));

    auto const metadata = AWAIT(ctx.encrypt(encryptedData, clearData));

    CHECK(T::extractResourceId(encryptedData) == metadata.resourceId);
  }
}

TEST_CASE("EncryptorV2 tests")
{
  TestContext<EncryptorV2> ctx;

  commonEncryptorTests(ctx);

  SECTION("encryptedSize should return the right size")
  {
    auto const versionSize = 1;
    constexpr auto MacSize = Trustchain::ResourceId::arraySize;
    constexpr auto IvSize = Crypto::AeadIv::arraySize;
    CHECK(EncryptorV2::encryptedSize(0) == versionSize + 0 + MacSize + IvSize);
    CHECK(EncryptorV2::encryptedSize(1) == versionSize + 1 + MacSize + IvSize);
  }
}

TEST_CASE("EncryptorV3 tests")
{
  TestContext<EncryptorV3> ctx;

  commonEncryptorTests(ctx);

  SECTION("encryptedSize should return the right size")
  {
    auto const versionSize = 1;
    constexpr auto MacSize = Trustchain::ResourceId::arraySize;
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

      TANKER_CHECK_THROWS_WITH_CODE(
          AWAIT_VOID(
              EncryptorV4::decrypt(decryptedData, metadata.key, truncatedData)),
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

  commonEncryptorTests(ctx);

  SECTION("encryptedSize should return the right size")
  {
    auto const versionSize = 1;
    constexpr auto ResourceIdSize = Trustchain::ResourceId::arraySize;
    constexpr auto IvSize = Crypto::AeadIv::arraySize;
    constexpr auto MacSize = Trustchain::ResourceId::arraySize;
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
