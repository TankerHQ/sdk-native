#include <Tanker/Functional/TrustchainFixture.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Encryptor/Padding.hpp>
#include <Tanker/Errors/Errc.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include <catch2/catch.hpp>
#include <optional>

#include "CheckDecrypt.hpp"

using namespace Tanker;
using namespace Tanker::Errors;
using Tanker::Functional::TrustchainFixture;
using namespace std::string_literals;

TEST_CASE_METHOD(TrustchainFixture, "Alice's session can encrypt for herself")
{
  auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession());

  std::string const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData(encSess.encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(
      TC_AWAIT(encSess.encrypt(encryptedData.data(), make_buffer(clearData))));

  REQUIRE_NOTHROW(
      TC_AWAIT(checkDecrypt({aliceSession}, clearData, encryptedData)));
}

TEST_CASE_METHOD(TrustchainFixture, "Alice's session can encrypt for Bob")
{
  auto encSess =
      TC_AWAIT(aliceSession->makeEncryptionSession({bob.spublicIdentity()}));

  std::string const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData(encSess.encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(
      TC_AWAIT(encSess.encrypt(encryptedData.data(), make_buffer(clearData))));

  REQUIRE_NOTHROW(
      TC_AWAIT(checkDecrypt({bobSession}, clearData, encryptedData)));
}

TEST_CASE_METHOD(TrustchainFixture,
                 "Alice can session-encrypt without sharing with self")
{
  auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession(
      {bob.spublicIdentity()}, {}, Core::ShareWithSelf::No));

  std::string const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData(encSess.encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(
      TC_AWAIT(encSess.encrypt(encryptedData.data(), make_buffer(clearData))));
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->decrypt(encryptedData)),
                                Errc::InvalidArgument);
  REQUIRE_NOTHROW(
      TC_AWAIT(checkDecrypt({bobSession}, clearData, encryptedData)));
}

TEST_CASE_METHOD(TrustchainFixture,
                 "Alice cannot session-encrypt without sharing with anybody")
{
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->makeEncryptionSession(
                                    {}, {}, Core::ShareWithSelf::No)),
                                Errc::InvalidArgument);
}

inline auto const sessionEncryptionOverhead = 57;

TEST_CASE_METHOD(TrustchainFixture,
                 "Alice can use the padding option with an encryption session")
{
  SECTION("session encrypt/decrypt with auto padding")
  {
    auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession(
        {}, {}, Core::ShareWithSelf::Yes, std::nullopt));

    auto const clearData = "my clear data is clear"s;
    auto const lengthWithPadme = 24;
    std::vector<uint8_t> encryptedData(encSess.encryptedSize(clearData.size()));
    REQUIRE_NOTHROW(TC_AWAIT(
        encSess.encrypt(encryptedData.data(), make_buffer(clearData))));

    CHECK(encryptedData.size() - sessionEncryptionOverhead ==
            lengthWithPadme);
    REQUIRE_NOTHROW(
        TC_AWAIT(checkDecrypt({aliceSession}, clearData, encryptedData)));
  }

  SECTION("session encrypt/decrypt with no padding")
  {
    auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession(
        {}, {}, Core::ShareWithSelf::Yes, Padding::Off));

    auto const clearData = "my clear data is clear"s;
    std::vector<uint8_t> encryptedData(encSess.encryptedSize(clearData.size()));
    REQUIRE_NOTHROW(TC_AWAIT(
        encSess.encrypt(encryptedData.data(), make_buffer(clearData))));

    CHECK(encryptedData.size() - sessionEncryptionOverhead == clearData.size());
    REQUIRE_NOTHROW(
        TC_AWAIT(checkDecrypt({aliceSession}, clearData, encryptedData)));
  }

  SECTION("session encrypt/decrypt with a padding step")
  {
    auto const step = 13;
    auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession(
        {}, {}, Core::ShareWithSelf::Yes, step));

    auto const clearData = "my clear data is clear"s;
    std::vector<uint8_t> encryptedData(encSess.encryptedSize(clearData.size()));
    REQUIRE_NOTHROW(TC_AWAIT(
        encSess.encrypt(encryptedData.data(), make_buffer(clearData))));

    CHECK((encryptedData.size() - sessionEncryptionOverhead) % step == 0);
    REQUIRE_NOTHROW(
        TC_AWAIT(checkDecrypt({aliceSession}, clearData, encryptedData)));
  }
}
