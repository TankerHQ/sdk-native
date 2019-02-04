#include <Tanker/EncryptionFormat/EncryptorV2.hpp>
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
