#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/EncryptionFormat/EncryptorV4.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Serialization/Varint.hpp>

#include <Helpers/Buffers.hpp>

#include <doctest.h>

using namespace Tanker;
using namespace EncryptionFormat;

namespace
{
constexpr auto encryptedChunkSize = 1024lu * 1024lu;
auto const versionSize = Serialization::varint_size(EncryptorV4::version());
}

TEST_CASE("decryptedSize and encryptedSize should be symmetrical")
{
  std::vector<uint8_t> a0(EncryptorV4::encryptedSize(0));
  Serialization::varint_write(a0.begin(), EncryptorV4::version());
  Serialization::varint_write(a0.begin() + versionSize, encryptedChunkSize);
  std::vector<uint8_t> a42(EncryptorV4::encryptedSize(42));
  Serialization::varint_write(a42.begin(), EncryptorV4::version());
  Serialization::varint_write(a42.begin() + versionSize, encryptedChunkSize);
  CHECK(EncryptorV4::decryptedSize(a0) == 0);
  CHECK(EncryptorV4::decryptedSize(a42) == 42);
}

TEST_CASE("encryptedSize should return the right size")
{
  constexpr auto MacSize = Crypto::Mac::arraySize;
  constexpr auto ResourceIdSize = MacSize;
  constexpr auto IvSize = Crypto::AeadIv::arraySize;

  CHECK(EncryptorV4::encryptedSize(0) ==
        versionSize + ResourceIdSize +
            Serialization::varint_size(encryptedChunkSize) + 0 + MacSize +
            IvSize);
  CHECK(EncryptorV4::encryptedSize(1) ==
        versionSize + ResourceIdSize +
            Serialization::varint_size(encryptedChunkSize) + 1 + MacSize +
            IvSize);
  auto const bigSize = 2 * 1024 * 1024 + 5;
  CHECK(EncryptorV4::encryptedSize(bigSize) ==
        versionSize + ResourceIdSize +
            Serialization::varint_size(encryptedChunkSize) + bigSize +
            3 * (MacSize + IvSize));
}

TEST_CASE("encrypt/decrypt should work with an empty buffer")
{
  std::vector<uint8_t> clearData;
  std::vector<uint8_t> encryptedData(
      EncryptorV4::encryptedSize(clearData.size()));
  auto const metadata = EncryptorV4::encrypt(encryptedData.data(), clearData);

  std::vector<uint8_t> decryptedData(EncryptorV4::decryptedSize(encryptedData));

  EncryptorV4::decrypt(decryptedData.data(), metadata.key, encryptedData);

  CHECK(clearData == decryptedData);
}

TEST_CASE("should not be able to decrypt a corrupted empty buffer")
{
  std::vector<uint8_t> clearData;
  std::vector<uint8_t> encryptedData(
      EncryptorV4::encryptedSize(clearData.size()));
  auto const metadata = EncryptorV4::encrypt(encryptedData.data(), clearData);
  encryptedData.back()++;

  std::vector<uint8_t> decryptedData(EncryptorV4::decryptedSize(encryptedData));

  CHECK_THROWS_AS(
      EncryptorV4::decrypt(decryptedData.data(), metadata.key, encryptedData),
      Error::DecryptFailed);
}

TEST_CASE("encrypt/decrypt should work with a normal buffer")
{
  auto clearData = make_buffer("this is the data to encrypt");
  std::vector<uint8_t> encryptedData(
      EncryptorV4::encryptedSize(clearData.size()));

  auto const metadata = EncryptorV4::encrypt(encryptedData.data(), clearData);

  std::vector<uint8_t> decryptedData(EncryptorV4::decryptedSize(encryptedData));

  EncryptorV4::decrypt(decryptedData.data(), metadata.key, encryptedData);

  CHECK(clearData == decryptedData);
}

TEST_CASE("encrypt/decrypt should work with a large buffer")
{
  std::vector<uint8_t> clearData(1024 * 1024 * 2 + 4);
  Crypto::randomFill(clearData);

  std::vector<uint8_t> encryptedData(
      EncryptorV4::encryptedSize(clearData.size()));

  auto const metadata = EncryptorV4::encrypt(encryptedData.data(), clearData);

  std::vector<uint8_t> decryptedData(EncryptorV4::decryptedSize(encryptedData));

  EncryptorV4::decrypt(decryptedData.data(), metadata.key, encryptedData);

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

  auto const metadata = EncryptorV4::encrypt(encryptedData.data(), clearData);

  std::vector<uint8_t> truncatedData(
      encryptedData.begin(),
      encryptedData.end() - Crypto::AeadIv::arraySize - Crypto::Mac::arraySize);

  std::vector<uint8_t> decryptedData(EncryptorV4::decryptedSize(truncatedData));

  CHECK_THROWS_AS(
      EncryptorV4::decrypt(decryptedData.data(), metadata.key, truncatedData),
      Error::DecryptFailed);
}

TEST_CASE("encrypt should never give the same result twice")
{
  auto clearData = make_buffer("this is the data to encrypt");
  std::vector<uint8_t> encryptedData1(
      EncryptorV4::encryptedSize(clearData.size()));
  EncryptorV4::encrypt(encryptedData1.data(), clearData);
  std::vector<uint8_t> encryptedData2(
      EncryptorV4::encryptedSize(clearData.size()));
  EncryptorV4::encrypt(encryptedData2.data(), clearData);

  CHECK(encryptedData1 != encryptedData2);
}

TEST_CASE("Should be able to decrypt an empty test buffer")
{
  std::vector<uint8_t> clearData;

  auto emptyTestVector = std::vector<uint8_t>(
      {0x4,  0x80, 0x80, 0x40, 0x5e, 0x44, 0x54, 0xa7, 0x83, 0x21, 0xd8, 0x77,
       0x8c, 0x7a, 0x25, 0xc9, 0x46, 0x52, 0xa,  0x60, 0x6a, 0xde, 0xf2, 0xa5,
       0xcb, 0xfa, 0xe6, 0x13, 0xf4, 0x2,  0x84, 0x27, 0x9c, 0x20, 0x1c, 0xb6,
       0x9f, 0x89, 0xc2, 0x8d, 0x7b, 0xc5, 0xf0, 0x1a, 0x19, 0x63, 0x7a, 0x4a,
       0xd7, 0xf9, 0xf9, 0xeb, 0x2c, 0x7e, 0xbb, 0xb1, 0x61, 0x65, 0x95, 0xdf});

  auto keyVector = std::vector<uint8_t>(
      {0xda, 0xa5, 0x3d, 0x7,  0xc,  0x4b, 0x63, 0x54, 0xe3, 0x6f, 0x96,
       0xc1, 0x14, 0x4c, 0x23, 0xcc, 0x16, 0x23, 0x52, 0xa1, 0xc5, 0x53,
       0xe3, 0xea, 0xd9, 0xc4, 0x1d, 0x28, 0x4c, 0x45, 0x43, 0xa9});

  std::vector<uint8_t> decryptedData(
      EncryptorV4::decryptedSize(emptyTestVector));

  EncryptorV4::decrypt(
      decryptedData.data(), Crypto::SymmetricKey{keyVector}, emptyTestVector);

  CHECK(clearData == decryptedData);
}

TEST_CASE("Should be able to decrypt a test vector V4")
{
  auto clearData = make_buffer("this is a secret");

  auto encryptedTestVector = std::vector<uint8_t>(
      {0x4,  0x80, 0x80, 0x40, 0xf2, 0x38, 0x50, 0x31, 0x6c, 0xfa, 0xaa,
       0x96, 0x8c, 0x1b, 0x25, 0x43, 0xf4, 0x38, 0xe3, 0x61, 0xcd, 0x59,
       0xb9, 0xb,  0x87, 0xff, 0x55, 0xde, 0xd1, 0xef, 0x9a, 0x99, 0xd3,
       0xcc, 0x6f, 0xa9, 0xe6, 0x78, 0xb2, 0x7b, 0x11, 0x5,  0xfa, 0xdc,
       0xa2, 0x4c, 0x77, 0x9a, 0xc8, 0xa4, 0xb3, 0xe7, 0x3f, 0x5e, 0xe5,
       0xf4, 0xbc, 0x86, 0xfc, 0x59, 0x1c, 0x72, 0xf0, 0x78, 0x80, 0x13,
       0x47, 0x9f, 0xd9, 0x96, 0xb2, 0xc7, 0x33, 0x26, 0xf5, 0x29});

  auto keyVector = std::vector<uint8_t>(
      {0xaf, 0x38, 0x67, 0x9d, 0x20, 0x56, 0x38, 0x6b, 0xef, 0xdd, 0x62,
       0x6d, 0x60, 0x1b, 0xf9, 0x39, 0xad, 0x71, 0x43, 0xc0, 0x30, 0x14,
       0xed, 0xea, 0x56, 0xff, 0x1f, 0x8a, 0x30, 0x90, 0xb6, 0x8b});

  std::vector<uint8_t> decryptedData(
      EncryptorV4::decryptedSize(encryptedTestVector));

  EncryptorV4::decrypt(decryptedData.data(),
                       Crypto::SymmetricKey{keyVector},
                       encryptedTestVector);

  CHECK(clearData == decryptedData);
}
