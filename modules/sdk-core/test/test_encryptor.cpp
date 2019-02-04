#include <Tanker/EncryptionFormat/EncryptorV2.hpp>
#include <Tanker/EncryptionFormat/EncryptorV3.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Serialization/Varint.hpp>

#include <Helpers/Buffers.hpp>

#include <doctest.h>

using namespace Tanker;

TEST_SUITE("EncryptorV2")
{
  TEST_CASE("decryptedSize and encryptedSize should be symmetrical")
  {
    std::vector<uint8_t> a0(EncryptionFormat::EncryptorV2::encryptedSize(0));
    Serialization::varint_write(a0.begin(),
                                EncryptionFormat::EncryptorV2::version());
    std::vector<uint8_t> a42(EncryptionFormat::EncryptorV2::encryptedSize(42));
    Serialization::varint_write(a42.begin(),
                                EncryptionFormat::EncryptorV2::version());
    CHECK(EncryptionFormat::EncryptorV2::decryptedSize(a0) == 0);
    CHECK(EncryptionFormat::EncryptorV2::decryptedSize(a42) == 42);
  }

  TEST_CASE(
      "decryptedSize should throw if the version is unsupported or the buffer "
      "is truncated")
  {
    auto const unsupportedBuffer = make_buffer("\42aaaaaaaaa");
    auto const truncatedBuffer = make_buffer("\2");
    CHECK_THROWS_AS(
        EncryptionFormat::EncryptorV2::decryptedSize(unsupportedBuffer),
        Error::VersionNotSupported);
    CHECK_THROWS_AS(
        EncryptionFormat::EncryptorV2::decryptedSize(truncatedBuffer),
        Error::DecryptFailed);
  }

  TEST_CASE("encryptedSize should return the right size")
  {
    auto const versionSize =
        Serialization::varint_size(EncryptionFormat::EncryptorV2::version());
    constexpr auto MacSize = Crypto::Mac::arraySize;
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
    auto const key = base64::decode<Crypto::SymmetricKey>(
        "XqV1NmaWWhDumAmjIg7SLckNO+UJczlclFFNGjgkZx0=");
    auto const encryptedData = base64::decode(
        "Ag40o25KiX7q4WjhCitEmYOBwGhZMTuPw+1j/"
        "Kuy+Nez89AWogT17gKzaViCZ13r7YhA9077CX1mwuxy");

    std::vector<uint8_t> decryptedData(
        EncryptionFormat::EncryptorV2::decryptedSize(encryptedData));
    EncryptionFormat::EncryptorV2::decrypt(
        decryptedData.data(), key, encryptedData);

    CHECK(decryptedData == clearData);
  }
}

TEST_SUITE("EncryptorV3")
{
  TEST_CASE("decryptedSize and encryptedSize should be symmetrical")
  {
    std::vector<uint8_t> a0(EncryptionFormat::EncryptorV3::encryptedSize(0));
    Serialization::varint_write(a0.begin(),
                                EncryptionFormat::EncryptorV3::version());
    std::vector<uint8_t> a42(EncryptionFormat::EncryptorV3::encryptedSize(42));
    Serialization::varint_write(a42.begin(),
                                EncryptionFormat::EncryptorV3::version());
    CHECK(EncryptionFormat::EncryptorV3::decryptedSize(a0) == 0);
    CHECK(EncryptionFormat::EncryptorV3::decryptedSize(a42) == 42);
  }

  TEST_CASE(
      "decryptedSize should throw if the version is unsupported or the buffer "
      "is truncated")
  {
    auto const unsupportedBuffer = make_buffer("\62aaaaaaaaa");
    auto const truncatedBuffer = make_buffer("\3");
    CHECK_THROWS_AS(
        EncryptionFormat::EncryptorV3::decryptedSize(unsupportedBuffer),
        Error::VersionNotSupported);
    CHECK_THROWS_AS(
        EncryptionFormat::EncryptorV3::decryptedSize(truncatedBuffer),
        Error::DecryptFailed);
  }

  TEST_CASE("encryptedSize should return the right size")
  {
    auto const versionSize =
        Serialization::varint_size(EncryptionFormat::EncryptorV3::version());
    constexpr auto MacSize = Crypto::Mac::arraySize;
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
    auto clearData = make_buffer("very secret test buffer");

    auto encryptedTestVector = std::vector<uint8_t>(
        {0x3,  0x89, 0x2c, 0x2a, 0x8e, 0xb,  0x62, 0x3f, 0x19, 0xd9,
         0xae, 0x47, 0x9c, 0x70, 0x23, 0xc5, 0x18, 0x75, 0xbd, 0x24,
         0x2,  0x79, 0x81, 0xec, 0x3d, 0xca, 0xe2, 0xc3, 0x14, 0xe1,
         0x91, 0x9b, 0xab, 0xa8, 0x7e, 0x2f, 0xa1, 0x77, 0x71, 0xae});

    auto keyVector = std::vector<uint8_t>(
        {0x20, 0xc0, 0x4f, 0xcf, 0x9d, 0x5a, 0xf9, 0x99, 0x5c, 0xf4, 0x51,
         0xef, 0xcc, 0xb3, 0xe3, 0x35, 0xc5, 0x4c, 0x4f, 0x7b, 0x20, 0x59,
         0x11, 0x97, 0x2d, 0x87, 0xe8, 0x6d, 0x4f, 0x62, 0xbc, 0xa1});

    std::vector<uint8_t> decryptedData(
        EncryptionFormat::EncryptorV3::decryptedSize(encryptedTestVector));

    EncryptionFormat::EncryptorV3::decrypt(decryptedData.data(),
                                           Crypto::SymmetricKey{keyVector},
                                           encryptedTestVector);

    CHECK(clearData == decryptedData);
  }
}
