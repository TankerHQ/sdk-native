#include <Tanker/Encryptor.hpp>
#include <Tanker/Error.hpp>

#include <Helpers/Buffers.hpp>

#include <doctest.h>

using namespace Tanker;

TEST_CASE("decryptedSize and encryptedSize should be symmetrical")
{
  std::vector<uint8_t> a0(Encryptor::encryptedSize(0));
  // 2 is the version
  a0[0] = 2;
  std::vector<uint8_t> a42(Encryptor::encryptedSize(42));
  a42[0] = 2;
  CHECK(Encryptor::decryptedSize(a0) == 0);
  CHECK(Encryptor::decryptedSize(a42) == 42);
}

TEST_CASE(
    "decryptedSize should throw if the version is unsupported or the buffer is "
    "truncated")
{
  auto const unsupportedBuffer = make_buffer("\42aaaaaaaaa");
  auto const truncatedBuffer = make_buffer("\2");
  CHECK_THROWS_AS(Encryptor::decryptedSize(unsupportedBuffer),
                  Error::VersionNotSupported);
  CHECK_THROWS_AS(Encryptor::decryptedSize(truncatedBuffer),
                  Error::DecryptFailed);
}

TEST_CASE("encryptedSize should return the right size")
{
  constexpr auto versionSize = 1;
  constexpr auto MacSize = 16;
  constexpr auto IvSize = 24;
  CHECK(Encryptor::encryptedSize(0) == versionSize + 0 + MacSize + IvSize);
  CHECK(Encryptor::encryptedSize(1) == versionSize + 1 + MacSize + IvSize);
}

TEST_CASE("encrypt/decrypt should work with an empty buffer")
{
  std::vector<uint8_t> clearData;
  std::vector<uint8_t> encryptedData(
      Encryptor::encryptedSize(clearData.size()));

  auto const metadata = Encryptor::encrypt(encryptedData.data(), clearData);

  std::vector<uint8_t> decryptedData(Encryptor::decryptedSize(encryptedData));

  Encryptor::decrypt(decryptedData.data(), metadata.key, encryptedData);

  CHECK(clearData == decryptedData);
}

TEST_CASE("encrypt/decrypt should work with a normal buffer")
{
  auto clearData = make_buffer("this is the data to encrypt");
  std::vector<uint8_t> encryptedData(
      Encryptor::encryptedSize(clearData.size()));

  auto const metadata = Encryptor::encrypt(encryptedData.data(), clearData);

  std::vector<uint8_t> decryptedData(Encryptor::decryptedSize(encryptedData));

  Encryptor::decrypt(decryptedData.data(), metadata.key, encryptedData);

  CHECK(clearData == decryptedData);
}

TEST_CASE("encrypt should never give the same result twice")
{
  auto clearData = make_buffer("this is the data to encrypt");
  std::vector<uint8_t> encryptedData1(
      Encryptor::encryptedSize(clearData.size()));
  Encryptor::encrypt(encryptedData1.data(), clearData);
  std::vector<uint8_t> encryptedData2(
      Encryptor::encryptedSize(clearData.size()));
  Encryptor::encrypt(encryptedData2.data(), clearData);

  CHECK(encryptedData1 != encryptedData2);
}

TEST_CASE("extractMac should give the same result as encrypt")
{
  auto clearData = make_buffer("this is the data to encrypt");
  std::vector<uint8_t> encryptedData(
      Encryptor::encryptedSize(clearData.size()));

  auto const metadata = Encryptor::encrypt(encryptedData.data(), clearData);

  CHECK(Encryptor::extractMac(encryptedData) == metadata.mac);
}

TEST_CASE("decrypt should work with a buffer v2")
{
  auto const clearData = make_buffer("this is very secret");
  auto const key = base64::decode<Crypto::SymmetricKey>(
      "XqV1NmaWWhDumAmjIg7SLckNO+UJczlclFFNGjgkZx0=");
  auto const encryptedData = base64::decode(
      "Ag40o25KiX7q4WjhCitEmYOBwGhZMTuPw+1j/"
      "Kuy+Nez89AWogT17gKzaViCZ13r7YhA9077CX1mwuxy");

  std::vector<uint8_t> decryptedData(Encryptor::decryptedSize(encryptedData));
  Encryptor::decrypt(decryptedData.data(), key, encryptedData);

  CHECK(decryptedData == clearData);
}
