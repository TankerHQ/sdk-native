#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Errors/Errc.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/Json/Json.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <cppcodec/base64_url.hpp>
#include <doctest/doctest.h>
#include <gsl/gsl-lite.hpp>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <vector>

using namespace Tanker;
using namespace Tanker::Crypto;
using namespace std::literals::string_literals;

TEST_CASE("encryptedSize and decryptedSize are correct")
{
  CHECK((10 + 16) == encryptedSize(10));
  CHECK(10 == decryptedSize(10 + 16));
  TANKER_CHECK_THROWS_WITH_CODE(decryptedSize(2),
                                Errc::InvalidEncryptedDataSize);
}

TEST_CASE("makeSymmetricKey should generate a key")
{
  auto const key = makeSymmetricKey();
  CHECK(!key.is_null());
}

TEST_CASE("aead")
{
  auto const buf =
      gsl::make_span("This is a test buffer").as_span<uint8_t const>();
  auto const key = makeSymmetricKey();

  SUBCASE("it should encrypt/decrypt an empty buffer")
  {
    std::vector<uint8_t> empty;
    std::vector<uint8_t> encryptedBuffer(encryptedSize(empty.size()));
    AeadIv iv{};
    encryptAead(key, iv.data(), encryptedBuffer.data(), empty, {});

    std::vector<uint8_t> decryptedBuffer(decryptedSize(encryptedBuffer.size()));
    decryptAead(key, iv.data(), decryptedBuffer.data(), encryptedBuffer, {});

    CHECK(decryptedBuffer.empty());
  }

  SUBCASE("it should encrypt/decrypt a buffer")
  {
    std::vector<uint8_t> encryptedBuffer(encryptedSize(buf.size()));
    AeadIv iv{};
    encryptAead(key, iv.data(), encryptedBuffer.data(), buf, {});

    std::vector<uint8_t> decryptedBuffer(decryptedSize(encryptedBuffer.size()));
    decryptAead(key, iv.data(), decryptedBuffer.data(), encryptedBuffer, {});

    CHECK(buf == gsl::make_span(decryptedBuffer));
  }

  SUBCASE("it should encrypt/decrypt a buffer smarter")
  {
    auto aeadBufferData = encryptAead(key, buf, {});
    auto aead = makeAeadBuffer<uint8_t>(aeadBufferData);

    // we copy the encrypted data
    std::vector<uint8_t> enc(aead.encryptedData.begin(),
                             aead.encryptedData.end());

    auto paf = decryptAead(key, aeadBufferData, {});

    REQUIRE_EQ(buf, gsl::make_span(paf));
  }

  SUBCASE("it should fail to decrypt a corrupted buffer")
  {
    std::vector<uint8_t> encryptedBuffer(encryptedSize(buf.size()));
    AeadIv iv{};
    encryptAead(key, iv.data(), encryptedBuffer.data(), buf, {});

    ++encryptedBuffer[0];

    std::vector<uint8_t> decryptedBuffer(decryptedSize(encryptedBuffer.size()));
    TANKER_CHECK_THROWS_WITH_CODE(
        decryptAead(
            key, iv.data(), decryptedBuffer.data(), encryptedBuffer, {}),
        Errc::AeadDecryptionFailed);
  }

  SUBCASE("it should encrypt/decrypt a buffer and verify additional data")
  {
    auto const additional =
        gsl::make_span("Another test buffer").as_span<const uint8_t>();

    std::vector<uint8_t> encryptedBuffer(encryptedSize(buf.size()));
    AeadIv iv{};
    encryptAead(key, iv.data(), encryptedBuffer.data(), buf, additional);

    std::vector<uint8_t> decryptedBuffer(decryptedSize(encryptedBuffer.size()));
    decryptAead(
        key, iv.data(), decryptedBuffer.data(), encryptedBuffer, additional);

    CHECK(buf == gsl::make_span(decryptedBuffer));
  }

  SUBCASE("it should fail to verify corrupted additional data")
  {
    auto additionals = std::string("Another test buffer");
    auto const additional =
        gsl::make_span(additionals.data(), additionals.size())
            .as_span<uint8_t const>();

    std::vector<uint8_t> encryptedBuffer(encryptedSize(buf.size()));
    AeadIv iv{};
    encryptAead(key, iv.data(), encryptedBuffer.data(), buf, additional);

    ++additionals[0];

    std::vector<uint8_t> decryptedBuffer(decryptedSize(encryptedBuffer.size()));
    TANKER_CHECK_THROWS_WITH_CODE(decryptAead(key,
                                              iv.data(),
                                              decryptedBuffer.data(),
                                              encryptedBuffer,
                                              additional),
                                  Errc::AeadDecryptionFailed);
  }

  SUBCASE("it should be able to derive an IV")
  {
    AeadIv iv{};
    randomFill(iv);
    auto const ivOne = deriveIv(iv, 1);
    auto const ivOneBis = deriveIv(iv, 1);
    auto const ivTwo = deriveIv(iv, 2);

    CHECK(ivOne == ivOneBis);
    CHECK(ivOne != ivTwo);
    CHECK(ivOne != iv);
  }
}

TEST_CASE("asymmetric")
{
  auto const buf =
      gsl::make_span("Yet another test buffer").as_span<uint8_t const>();
  auto const aliceKeyPair = makeEncryptionKeyPair();
  auto const bobKeyPair = makeEncryptionKeyPair();

  SUBCASE("it should encrypt/decrypt a buffer")
  {
    auto const enc =
        asymEncrypt(buf, aliceKeyPair.privateKey, bobKeyPair.publicKey);
    auto const dec =
        asymDecrypt(enc, aliceKeyPair.publicKey, bobKeyPair.privateKey);

    CHECK(gsl::make_span(dec) == buf);
  }

  SUBCASE("it should fail to decrypt a corrupted buffer")
  {
    auto enc = asymEncrypt(buf, aliceKeyPair.privateKey, bobKeyPair.publicKey);
    ++enc[8];
    TANKER_CHECK_THROWS_WITH_CODE(
        asymDecrypt(enc, aliceKeyPair.publicKey, bobKeyPair.privateKey),
        Errc::AsymmetricDecryptionFailed);
  }

  SUBCASE("it should fail to decrypt a buffer too small")
  {
    std::vector<uint8_t> enc(5);
    TANKER_CHECK_THROWS_WITH_CODE(
        asymDecrypt(enc, aliceKeyPair.publicKey, bobKeyPair.privateKey),
        Errc::InvalidEncryptedDataSize);
  }

  SUBCASE("it should fail to decrypt with the wrong key")
  {
    auto const charlieKeyPair = makeEncryptionKeyPair();

    auto enc = asymEncrypt(buf, aliceKeyPair.privateKey, bobKeyPair.publicKey);
    TANKER_CHECK_THROWS_WITH_CODE(
        asymDecrypt(enc, aliceKeyPair.publicKey, charlieKeyPair.privateKey),
        Errc::AsymmetricDecryptionFailed);
  }

  SUBCASE("it should make encryption keypair from private encryption key")
  {
    auto const privateKey =
        make<PrivateEncryptionKey>("This is a private encryption key");
    auto kp = makeEncryptionKeyPair(privateKey);
    CHECK(kp.privateKey == privateKey);
  }

  SUBCASE("it should make signature keypair from private signature key")
  {
    auto const originalKeyPair = makeSignatureKeyPair();
    auto kp = makeSignatureKeyPair(originalKeyPair.privateKey);
    CHECK(kp.privateKey == originalKeyPair.privateKey);
    CHECK(kp.publicKey == originalKeyPair.publicKey);
    SUBCASE("Check if the keypair works")
    {
      auto data = Tanker::make_buffer("signed by ..."s);
      auto sig = sign(data, kp.privateKey);
      CHECK(verify(data, sig, kp.publicKey));
    }
  }

  SUBCASE("it should derive public signature key from private key")
  {
    auto const keyPair = makeSignatureKeyPair();
    CHECK(derivePublicKey(keyPair.privateKey) == keyPair.publicKey);
  }

  SUBCASE("it should derive public encryption key from private key")
  {
    auto const keyPair = makeEncryptionKeyPair();
    CHECK(derivePublicKey(keyPair.privateKey) == keyPair.publicKey);
  }
}

TEST_CASE("asymmetric seal")
{
  auto const buf = gsl::make_span("Test buffer").as_span<uint8_t const>();
  auto const bobKeyPair = makeEncryptionKeyPair();

  SUBCASE("it should encrypt/decrypt an empty buffer")
  {
    std::vector<uint8_t> empty;
    auto const enc = sealEncrypt(empty, bobKeyPair.publicKey);
    auto const dec = sealDecrypt(enc, bobKeyPair);

    CHECK(dec.empty());
  }

  SUBCASE("it should encrypt/decrypt a buffer")
  {
    auto const enc = sealEncrypt(buf, bobKeyPair.publicKey);
    auto const dec = sealDecrypt(enc, bobKeyPair);

    CHECK(gsl::make_span(dec) == buf);
  }

  SUBCASE("it should fail to decrypt a corrupted buffer")
  {
    auto enc = sealEncrypt(buf, bobKeyPair.publicKey);
    ++enc[8];
    TANKER_CHECK_THROWS_WITH_CODE(sealDecrypt(enc, bobKeyPair),
                                  Errc::SealedDecryptionFailed);
  }

  SUBCASE("it should fail to decrypt a buffer too small")
  {
    std::vector<uint8_t> enc(5);
    TANKER_CHECK_THROWS_WITH_CODE(sealDecrypt(enc, bobKeyPair),
                                  Errc::InvalidSealedDataSize);
  }

  SUBCASE("it should fail to decrypt with the wrong key")
  {
    auto const charlieKeyPair = makeEncryptionKeyPair();

    auto enc = sealEncrypt(buf, bobKeyPair.publicKey);
    TANKER_CHECK_THROWS_WITH_CODE(sealDecrypt(enc, charlieKeyPair),
                                  Errc::SealedDecryptionFailed);
  }
}

TEST_CASE("prehashPassword")
{
  SUBCASE("throw on empty password")
  {
    TANKER_CHECK_THROWS_WITH_CODE(prehashPassword(""), Errc::InvalidBufferSize);
  }

  SUBCASE("should match our test vector")
  {
    auto const input = "super secretive password";
    auto const expected = cppcodec::base64_rfc4648::decode<Hash>(
        "UYNRgDLSClFWKsJ7dl9uPJjhpIoEzadksv/Mf44gSHI=");

    CHECK_EQ(prehashPassword(input), expected);
  }

  SUBCASE("should match our test vector")
  {
    // "test éå 한국어 😃"
    char const input[] =
        "\x74\x65\x73\x74\x20\xc3\xa9\xc3\xa5\x20\xed\x95\x9c\xea\xb5\xad\xec"
        "\x96\xb4\x20\xf0\x9f\x98\x83";
    auto const expected = cppcodec::base64_rfc4648::decode<Hash>(
        "Pkn/pjub2uwkBDpt2HUieWOXP5xLn0Zlen16ID4C7jI=");

    CHECK_EQ(prehashPassword(input), expected);
  }
}

template <typename T>
void test_format(T const& var)
{
  SUBCASE("be implicitly encoded")
  {
    auto formated = fmt::format("{}", var);
    REQUIRE_EQ(formated, cppcodec::base64_rfc4648::encode(var));
  }
  SUBCASE("be annoyingly encoded")
  {
    auto formated = fmt::format("{:}", var);
    REQUIRE_EQ(formated, cppcodec::base64_rfc4648::encode(var));
  }
  SUBCASE("be safely encoded")
  {
    auto formated = fmt::format("{:S}", var);
    REQUIRE_EQ(formated, cppcodec::base64_url::encode(var));
  }
  SUBCASE("be explicitly encoded")
  {
    auto formated = fmt::format("{:s}", var);
    REQUIRE_EQ(formated, cppcodec::base64_rfc4648::encode(var));
  }
  SUBCASE("be jsonifiyed")
  {
    REQUIRE_EQ(nlohmann::json(var), cppcodec::base64_rfc4648::encode(var));
  }
  SUBCASE("complain")
  {
    REQUIRE_THROWS_AS(fmt::format("{", var), fmt::format_error);
  }
}

TEST_CASE("format hash")
{
  test_format(make<Hash>("Hash content"));
}

TEST_CASE("format mac")
{
  test_format(make<Mac>("Mac content"));
}

TEST_CASE("format signature")
{
  test_format(make<Signature>("signed by ..."));
}

TEST_CASE("format symmetrickey")
{
  test_format(make<SymmetricKey>("SymmetricKey content"));
}
TEST_CASE("format PrivateSignatureKey")
{
  test_format(make<PrivateSignatureKey>("PrivateSignatureKey content"));
}
TEST_CASE("format PublicSignatureKey")
{
  test_format(make<PublicSignatureKey>("PublicSignatureKey content"));
}
TEST_CASE("format PrivateEncryptionKey")
{
  test_format(make<PrivateEncryptionKey>("PrivateEncryptionKey content"));
}
TEST_CASE("format PublicEncryptionKey")
{
  test_format(make<PublicEncryptionKey>("PublicEncryptionKey content"));
}
