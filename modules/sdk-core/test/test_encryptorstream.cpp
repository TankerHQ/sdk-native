#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Encryptor/v4.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Serialization/Varint.hpp>
#include <Tanker/Streams/Header.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include <doctest.h>
#include <iostream>

using namespace Tanker;
using namespace Tanker::Errors;

TEST_SUITE("Stream encryption tests")
{
  TEST_CASE("decryptedSize and encryptedSize should be symmetrical")
  {
    std::vector<uint8_t> a0(EncryptorV4::encryptedSize(0));
    auto it0 = a0.data();
    it0 = Serialization::varint_write(it0, EncryptorV4::version());
    Serialization::varint_write(it0, Streams::Header::defaultEncryptedChunkSize);

    std::vector<uint8_t> a42(EncryptorV4::encryptedSize(42));
    auto it42 = a42.data();
    it42 = Serialization::varint_write(it42, EncryptorV4::version());
    Serialization::varint_write(it42, Streams::Header::defaultEncryptedChunkSize);
    CHECK(EncryptorV4::decryptedSize(a0) == 0);
    CHECK(EncryptorV4::decryptedSize(a42) == 42);
  }

  TEST_CASE("encryptedSize should return the right size")
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

  TEST_CASE("encrypt/decrypt should work with an empty buffer")
  {
    std::vector<uint8_t> clearData;
    std::vector<uint8_t> encryptedData(
        EncryptorV4::encryptedSize(clearData.size()));
    auto const metadata =
        AWAIT(EncryptorV4::encrypt(encryptedData.data(), clearData));

    std::vector<uint8_t> decryptedData(
        EncryptorV4::decryptedSize(encryptedData));

    AWAIT_VOID(EncryptorV4::decrypt(
        decryptedData.data(), metadata.key, encryptedData));

    CHECK(clearData == decryptedData);
  }

  TEST_CASE("should not be able to decrypt a corrupted empty buffer")
  {
    std::vector<uint8_t> clearData;
    std::vector<uint8_t> encryptedData(
        EncryptorV4::encryptedSize(clearData.size()));
    auto const metadata =
        AWAIT(EncryptorV4::encrypt(encryptedData.data(), clearData));
    encryptedData.back()++;

    std::vector<uint8_t> decryptedData(
        EncryptorV4::decryptedSize(encryptedData));

    TANKER_CHECK_THROWS_WITH_CODE(
        AWAIT_VOID(EncryptorV4::decrypt(
            decryptedData.data(), metadata.key, encryptedData)),
        Errc::DecryptionFailed);
  }

  TEST_CASE("encrypt/decrypt should work with a normal buffer")
  {
    auto clearData = make_buffer("this is the data to encrypt");
    std::vector<uint8_t> encryptedData(
        EncryptorV4::encryptedSize(clearData.size()));

    auto const metadata =
        AWAIT(EncryptorV4::encrypt(encryptedData.data(), clearData));

    std::vector<uint8_t> decryptedData(
        EncryptorV4::decryptedSize(encryptedData));

    AWAIT_VOID(EncryptorV4::decrypt(
        decryptedData.data(), metadata.key, encryptedData));

    CHECK(clearData == decryptedData);
  }

  TEST_CASE("encrypt/decrypt should work with a large buffer")
  {
    std::vector<uint8_t> clearData(Streams::Header::defaultEncryptedChunkSize * 2 +
                                   4);
    Crypto::randomFill(clearData);

    std::vector<uint8_t> encryptedData(
        EncryptorV4::encryptedSize(clearData.size()));

    auto const metadata =
        AWAIT(EncryptorV4::encrypt(encryptedData.data(), clearData));

    std::vector<uint8_t> decryptedData(
        EncryptorV4::decryptedSize(encryptedData));

    AWAIT_VOID(EncryptorV4::decrypt(
        decryptedData.data(), metadata.key, encryptedData));

    CHECK(clearData == decryptedData);
  }

  TEST_CASE("Should not be able to decrypt a buffer without the last chunk")
  {
    // This data is supposed to be exactly one chunk so a second chunk will be
    // added to guarantee the integrity of the data
    std::vector<uint8_t> clearData(1024 * 1024);
    Crypto::randomFill(clearData);

    std::vector<uint8_t> encryptedData(
        EncryptorV4::encryptedSize(clearData.size()));

    auto const metadata =
        AWAIT(EncryptorV4::encrypt(encryptedData.data(), clearData));

    std::vector<uint8_t> truncatedData(encryptedData.begin(),
                                       encryptedData.end() -
                                           Crypto::AeadIv::arraySize -
                                           Trustchain::ResourceId::arraySize);

    std::vector<uint8_t> decryptedData(
        EncryptorV4::decryptedSize(truncatedData));

    TANKER_CHECK_THROWS_WITH_CODE(
        AWAIT_VOID(EncryptorV4::decrypt(
            decryptedData.data(), metadata.key, truncatedData)),
        Errc::DecryptionFailed);
  }

  TEST_CASE("encrypt should never give the same result twice")
  {
    auto clearData = make_buffer("this is the data to encrypt");
    std::vector<uint8_t> encryptedData1(
        EncryptorV4::encryptedSize(clearData.size()));
    AWAIT(EncryptorV4::encrypt(encryptedData1.data(), clearData));
    std::vector<uint8_t> encryptedData2(
        EncryptorV4::encryptedSize(clearData.size()));
    AWAIT(EncryptorV4::encrypt(encryptedData2.data(), clearData));

    CHECK(encryptedData1 != encryptedData2);
  }

  TEST_CASE("Should be able to decrypt an empty test buffer")
  {
    std::vector<uint8_t> clearData;

    auto emptyTestVector = std::vector<uint8_t>(
        {0x4,  0x0,  0x0,  0x10, 0x0,  0x5e, 0x44, 0x54, 0xa7, 0x83, 0x21,
         0xd8, 0x77, 0x8c, 0x7a, 0x25, 0xc9, 0x46, 0x52, 0xa,  0x60, 0x1d,
         0xb1, 0x25, 0xaf, 0x1e, 0x85, 0x84, 0xa9, 0xcf, 0x19, 0x71, 0x26,
         0x79, 0xf3, 0x47, 0xd1, 0xf6, 0xf0, 0xf7, 0x2,  0x85, 0x47, 0xfb,
         0xe8, 0x5e, 0x16, 0x25, 0x33, 0xf6, 0x66, 0x7b, 0xb9, 0xd5, 0xa5,
         0x1d, 0xe9, 0x23, 0x71, 0xb,  0x75});

    auto keyVector = std::vector<uint8_t>(
        {0xda, 0xa5, 0x3d, 0x7,  0xc,  0x4b, 0x63, 0x54, 0xe3, 0x6f, 0x96,
         0xc1, 0x14, 0x4c, 0x23, 0xcc, 0x16, 0x23, 0x52, 0xa1, 0xc5, 0x53,
         0xe3, 0xea, 0xd9, 0xc4, 0x1d, 0x28, 0x4c, 0x45, 0x43, 0xa9});

    std::vector<uint8_t> decryptedData(
        EncryptorV4::decryptedSize(emptyTestVector));

    AWAIT_VOID(EncryptorV4::decrypt(decryptedData.data(),
                                    Crypto::SymmetricKey{keyVector},
                                    emptyTestVector));

    CHECK(clearData == decryptedData);
  }

  TEST_CASE("Should be able to decrypt a test vector V4")
  {
    auto clearData = make_buffer("this is a secret");

    auto encryptedTestVector = std::vector<uint8_t>(
        {0x4,  0x0,  0x0,  0x10, 0x0,  0xf2, 0x38, 0x50, 0x31, 0x6c, 0xfa,
         0xaa, 0x96, 0x8c, 0x1b, 0x25, 0x43, 0xf4, 0x38, 0xe3, 0x61, 0x55,
         0x24, 0x50, 0xe8, 0x3b, 0x3,  0xe9, 0xf6, 0x1,  0xf1, 0x73, 0x5f,
         0x3e, 0x52, 0xb2, 0x8f, 0xc0, 0x1f, 0xd,  0xcd, 0xac, 0x8f, 0x5,
         0x2a, 0xbd, 0x31, 0x32, 0xe,  0x16, 0xdd, 0x20, 0x40, 0x58, 0xa2,
         0xfe, 0xc6, 0xf3, 0x5d, 0xff, 0x25, 0xe8, 0xc9, 0x33, 0xc1, 0x8,
         0xe0, 0xb1, 0xb0, 0xb,  0xe4, 0x86, 0x8c, 0x36, 0xb8, 0x2f, 0xbf});

    auto keyVector = std::vector<uint8_t>(
        {0xaf, 0x38, 0x67, 0x9d, 0x20, 0x56, 0x38, 0x6b, 0xef, 0xdd, 0x62,
         0x6d, 0x60, 0x1b, 0xf9, 0x39, 0xad, 0x71, 0x43, 0xc0, 0x30, 0x14,
         0xed, 0xea, 0x56, 0xff, 0x1f, 0x8a, 0x30, 0x90, 0xb6, 0x8b});

    std::vector<uint8_t> decryptedData(
        EncryptorV4::decryptedSize(encryptedTestVector));

    AWAIT_VOID(EncryptorV4::decrypt(decryptedData.data(),
                                    Crypto::SymmetricKey{keyVector},
                                    encryptedTestVector));

    CHECK(clearData == decryptedData);
  }

  TEST_CASE("Should be able to decrypt a test vector V4 with multiple chunks")
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

    auto keyVector = std::vector<uint8_t>(
        {0xa,  0x7,  0x3d, 0xd0, 0x2c, 0x2d, 0x17, 0xf9, 0x49, 0xd9, 0x35,
         0x8e, 0xf7, 0xfe, 0x7b, 0xd1, 0xf6, 0xb,  0xf1, 0x5c, 0xa4, 0x32,
         0x1e, 0xe4, 0xaa, 0x18, 0xe1, 0x97, 0xbf, 0xf4, 0x5e, 0xfe});

    std::vector<uint8_t> decryptedData(
        EncryptorV4::decryptedSize(encryptedTestVector));

    AWAIT_VOID(EncryptorV4::decrypt(decryptedData.data(),
                                    Crypto::SymmetricKey{keyVector},
                                    encryptedTestVector));

    CHECK(clearData == decryptedData);
  }
}
