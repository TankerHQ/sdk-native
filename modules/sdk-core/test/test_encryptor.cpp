#include <Tanker/Crypto/AeadIv.hpp>
#include <Tanker/EncryptionFormat/EncryptorV2.hpp>
#include <Tanker/EncryptionFormat/EncryptorV3.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Serialization/Varint.hpp>

#include <Helpers/Buffers.hpp>

#include <doctest.h>

using namespace Tanker;

TEST_SUITE("EncryptorV2")
{
  auto const keyVector = Crypto::SymmetricKey(std::vector<uint8_t>(
      {0x76, 0xd,  0x8e, 0x80, 0x5c, 0xbc, 0xa8, 0xb6, 0xda, 0xea, 0xcf,
       0x66, 0x46, 0xca, 0xd7, 0xeb, 0x4f, 0x3a, 0xbc, 0x69, 0xac, 0x9b,
       0xce, 0x77, 0x35, 0x8e, 0xa8, 0x31, 0xd7, 0x2f, 0x14, 0xdd}));

  auto encryptedTestVector = std::vector<uint8_t>(
      {0x02, 0x32, 0x93, 0xa3, 0xf8, 0x6c, 0xa8, 0x82, 0x25, 0xbc, 0x17, 0x7e,
       0xb5, 0x65, 0x9b, 0xee, 0xd,  0xfd, 0xcf, 0xc6, 0x5c, 0x6d, 0xb4, 0x72,
       0xe0, 0x5b, 0x33, 0x27, 0x4c, 0x83, 0x84, 0xd1, 0xad, 0xda, 0x5f, 0x86,
       0x2,  0x46, 0x42, 0x91, 0x71, 0x30, 0x65, 0x2e, 0x72, 0x47, 0xe6, 0x48,
       0x20, 0xa1, 0x86, 0x91, 0x7f, 0x9c, 0xb5, 0x5e, 0x91, 0xb3, 0x65, 0x2d});

  TEST_CASE("decryptedSize and encryptedSize should be symmetrical")
  {
    std::vector<uint8_t> a0(EncryptionFormat::EncryptorV2::encryptedSize(0));
    Serialization::varint_write(a0.data(),
                                EncryptionFormat::EncryptorV2::version());
    std::vector<uint8_t> a42(EncryptionFormat::EncryptorV2::encryptedSize(42));
    Serialization::varint_write(a42.data(),
                                EncryptionFormat::EncryptorV2::version());
    CHECK(EncryptionFormat::EncryptorV2::decryptedSize(a0) == 0);
    CHECK(EncryptionFormat::EncryptorV2::decryptedSize(a42) == 42);
  }

  TEST_CASE("decryptedSize should throw if the buffer is truncated")
  {
    auto const truncatedBuffer = make_buffer("\2");
    CHECK_THROWS_AS(
        EncryptionFormat::EncryptorV2::decryptedSize(truncatedBuffer),
        Error::InvalidArgument);
  }

  TEST_CASE("encryptedSize should return the right size")
  {
    auto const versionSize =
        Serialization::varint_size(EncryptionFormat::EncryptorV2::version());
    constexpr auto MacSize = Trustchain::ResourceId::arraySize;
    constexpr auto IvSize = Crypto::AeadIv::arraySize;
    CHECK(EncryptionFormat::EncryptorV2::encryptedSize(0) ==
          versionSize + 0 + MacSize + IvSize);
    CHECK(EncryptionFormat::EncryptorV2::encryptedSize(1) ==
          versionSize + 1 + MacSize + IvSize);
  }

  TEST_CASE("encrypt/decrypt should work with an empty buffer")
  {
    std::vector<uint8_t> clearData;
    std::vector<uint8_t> encryptedData(
        EncryptionFormat::EncryptorV2::encryptedSize(clearData.size()));

    auto const metadata =
        EncryptionFormat::EncryptorV2::encrypt(encryptedData.data(), clearData);

    std::vector<uint8_t> decryptedData(
        EncryptionFormat::EncryptorV2::decryptedSize(encryptedData));

    EncryptionFormat::EncryptorV2::decrypt(
        decryptedData.data(), metadata.key, encryptedData);

    CHECK(clearData == decryptedData);
  }

  TEST_CASE("encrypt/decrypt should work with a normal buffer")
  {
    auto clearData = make_buffer("this is the data to encrypt");
    std::vector<uint8_t> encryptedData(
        EncryptionFormat::EncryptorV2::encryptedSize(clearData.size()));

    auto const metadata =
        EncryptionFormat::EncryptorV2::encrypt(encryptedData.data(), clearData);

    std::vector<uint8_t> decryptedData(
        EncryptionFormat::EncryptorV2::decryptedSize(encryptedData));

    EncryptionFormat::EncryptorV2::decrypt(
        decryptedData.data(), metadata.key, encryptedData);

    CHECK(clearData == decryptedData);
  }

  TEST_CASE("encrypt should never give the same result twice")
  {
    auto clearData = make_buffer("this is the data to encrypt");
    std::vector<uint8_t> encryptedData1(
        EncryptionFormat::EncryptorV2::encryptedSize(clearData.size()));
    EncryptionFormat::EncryptorV2::encrypt(encryptedData1.data(), clearData);
    std::vector<uint8_t> encryptedData2(
        EncryptionFormat::EncryptorV2::encryptedSize(clearData.size()));
    EncryptionFormat::EncryptorV2::encrypt(encryptedData2.data(), clearData);

    CHECK(encryptedData1 != encryptedData2);
  }

  TEST_CASE("extractResourceId should give the same result as encrypt")
  {
    auto clearData = make_buffer("this is the data to encrypt");
    std::vector<uint8_t> encryptedData(
        EncryptionFormat::EncryptorV2::encryptedSize(clearData.size()));

    auto const metadata =
        EncryptionFormat::EncryptorV2::encrypt(encryptedData.data(), clearData);

    CHECK(EncryptionFormat::EncryptorV2::extractResourceId(encryptedData) ==
          metadata.resourceId);
  }

  TEST_CASE("decrypt should work with a buffer v2")
  {
    auto const clearData = make_buffer("this is very secret");

    std::vector<uint8_t> decryptedData(
        EncryptionFormat::EncryptorV2::decryptedSize(encryptedTestVector));
    EncryptionFormat::EncryptorV2::decrypt(
        decryptedData.data(), keyVector, encryptedTestVector);

    CHECK(decryptedData == clearData);
  }

  TEST_CASE("decrypt should not work with a corrupted buffer v2")
  {
    auto const clearData = make_buffer("this is very secret");

    std::vector<uint8_t> decryptedData(
        EncryptionFormat::EncryptorV2::decryptedSize(encryptedTestVector));

    encryptedTestVector[2]++;

    CHECK_THROWS_AS(EncryptionFormat::EncryptorV2::decrypt(
                        decryptedData.data(), keyVector, encryptedTestVector),
                    Error::DecryptFailed);
  }
}

TEST_SUITE("EncryptorV3")
{
  auto const keyVector = Crypto::SymmetricKey(std::vector<uint8_t>(
      {0x76, 0xd,  0x8e, 0x80, 0x5c, 0xbc, 0xa8, 0xb6, 0xda, 0xea, 0xcf,
       0x66, 0x46, 0xca, 0xd7, 0xeb, 0x4f, 0x3a, 0xbc, 0x69, 0xac, 0x9b,
       0xce, 0x77, 0x35, 0x8e, 0xa8, 0x31, 0xd7, 0x2f, 0x14, 0xdd}));

  auto encryptedTestVector = std::vector<uint8_t>(
      {0x03, 0x37, 0xb5, 0x3d, 0x55, 0x34, 0xb5, 0xc1, 0x3f, 0xe3, 0x72, 0x81,
       0x47, 0xf0, 0xca, 0xda, 0x29, 0x99, 0x6e, 0x4,  0xa8, 0x41, 0x81, 0xa0,
       0xe0, 0x5e, 0x8e, 0x3a, 0x8,  0xd3, 0x78, 0xfa, 0x5,  0x9f, 0x17, 0xfa});

  TEST_CASE("decryptedSize and encryptedSize should be symmetrical")
  {
    std::vector<uint8_t> a0(EncryptionFormat::EncryptorV3::encryptedSize(0));
    Serialization::varint_write(a0.data(),
                                EncryptionFormat::EncryptorV3::version());
    std::vector<uint8_t> a42(EncryptionFormat::EncryptorV3::encryptedSize(42));
    Serialization::varint_write(a42.data(),
                                EncryptionFormat::EncryptorV3::version());
    CHECK(EncryptionFormat::EncryptorV3::decryptedSize(a0) == 0);
    CHECK(EncryptionFormat::EncryptorV3::decryptedSize(a42) == 42);
  }

  TEST_CASE("decryptedSize should throw if the buffer is truncated")
  {
    auto const truncatedBuffer = make_buffer("\3");
    CHECK_THROWS_AS(
        EncryptionFormat::EncryptorV3::decryptedSize(truncatedBuffer),
        Error::InvalidArgument);
  }

  TEST_CASE("encryptedSize should return the right size")
  {
    auto const versionSize =
        Serialization::varint_size(EncryptionFormat::EncryptorV3::version());
    constexpr auto MacSize = Trustchain::ResourceId::arraySize;
    CHECK(EncryptionFormat::EncryptorV3::encryptedSize(0) ==
          versionSize + 0 + MacSize);
    CHECK(EncryptionFormat::EncryptorV3::encryptedSize(1) ==
          versionSize + 1 + MacSize);
  }

  TEST_CASE("encrypt/decrypt should work with an empty buffer")
  {
    std::vector<uint8_t> clearData;
    std::vector<uint8_t> encryptedData(
        EncryptionFormat::EncryptorV3::encryptedSize(clearData.size()));

    auto const metadata =
        EncryptionFormat::EncryptorV3::encrypt(encryptedData.data(), clearData);

    std::vector<uint8_t> decryptedData(
        EncryptionFormat::EncryptorV3::decryptedSize(encryptedData));

    EncryptionFormat::EncryptorV3::decrypt(
        decryptedData.data(), metadata.key, encryptedData);

    CHECK(clearData == decryptedData);
  }

  TEST_CASE("encrypt/decrypt should work with a normal buffer")
  {
    auto clearData = make_buffer("this is the data to encrypt");
    std::vector<uint8_t> encryptedData(
        EncryptionFormat::EncryptorV3::encryptedSize(clearData.size()));

    auto const metadata =
        EncryptionFormat::EncryptorV3::encrypt(encryptedData.data(), clearData);

    std::vector<uint8_t> decryptedData(
        EncryptionFormat::EncryptorV3::decryptedSize(encryptedData));

    EncryptionFormat::EncryptorV3::decrypt(
        decryptedData.data(), metadata.key, encryptedData);

    CHECK(clearData == decryptedData);
  }

  TEST_CASE("encrypt should never give the same result twice")
  {
    auto clearData = make_buffer("this is the data to encrypt");
    std::vector<uint8_t> encryptedData1(
        EncryptionFormat::EncryptorV3::encryptedSize(clearData.size()));
    EncryptionFormat::EncryptorV3::encrypt(encryptedData1.data(), clearData);
    std::vector<uint8_t> encryptedData2(
        EncryptionFormat::EncryptorV3::encryptedSize(clearData.size()));
    EncryptionFormat::EncryptorV3::encrypt(encryptedData2.data(), clearData);

    CHECK(encryptedData1 != encryptedData2);
  }

  TEST_CASE("extractResourceId should give the same result as encrypt")
  {
    auto clearData = make_buffer("this is the data to encrypt");
    std::vector<uint8_t> encryptedData(
        EncryptionFormat::EncryptorV3::encryptedSize(clearData.size()));

    auto const metadata =
        EncryptionFormat::EncryptorV3::encrypt(encryptedData.data(), clearData);

    CHECK(EncryptionFormat::EncryptorV3::extractResourceId(encryptedData) ==
          metadata.resourceId);
  }

  TEST_CASE("decrypt should work with a buffer v3")
  {
    auto clearData = make_buffer("this is very secret");

    std::vector<uint8_t> decryptedData(
        EncryptionFormat::EncryptorV3::decryptedSize(encryptedTestVector));

    EncryptionFormat::EncryptorV3::decrypt(
        decryptedData.data(), keyVector, encryptedTestVector);

    CHECK(clearData == decryptedData);
  }

  TEST_CASE("decrypt should not work with a corrupted buffer v3")
  {
    auto const clearData = make_buffer("this is very secret");

    std::vector<uint8_t> decryptedData(
        EncryptionFormat::EncryptorV3::decryptedSize(encryptedTestVector));
    encryptedTestVector[2]++;

    CHECK_THROWS_AS(EncryptionFormat::EncryptorV3::decrypt(
                        decryptedData.data(), keyVector, encryptedTestVector),
                    Error::DecryptFailed);
  }
}
