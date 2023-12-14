#include <Tanker/Functional/TrustchainFixture.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Encryptor/v4.hpp>
#include <Tanker/Encryptor/v8.hpp>
#include <Tanker/Errors/Errc.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include "TestSuite.hpp"
#include <optional>

#include "CheckDecrypt.hpp"

using namespace Tanker;
using namespace Tanker::Errors;
using Tanker::Crypto::ResourceId;
using Tanker::Functional::TrustchainFixture;
using namespace std::string_literals;

namespace
{
constexpr auto fiveMiB = 5 * 1024 * 1024;
constexpr auto almostFiveMiB = fiveMiB - 30;
}

TEST_CASE_METHOD(TrustchainFixture, "Alice's session can encrypt for herself")
{
  auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession());

  std::string const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData(encSess.encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(TC_AWAIT(encSess.encrypt(encryptedData, make_buffer(clearData))));

  REQUIRE_NOTHROW(TC_AWAIT(checkDecrypt({aliceSession}, clearData, encryptedData)));
  CHECK(Core::getResourceId(encryptedData) == ResourceId{encSess.resourceId()});
}

TEST_CASE_METHOD(TrustchainFixture, "Alice's session can encrypt a huge resource")
{
  auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession());

  std::string clearData(fiveMiB, 42);
  std::vector<uint8_t> encryptedData(encSess.encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(TC_AWAIT(encSess.encrypt(encryptedData, make_buffer(clearData))));

  REQUIRE_NOTHROW(TC_AWAIT(checkDecrypt({aliceSession}, clearData, encryptedData)));
  CHECK(Core::getResourceId(encryptedData) == ResourceId{encSess.resourceId()});
}

TEST_CASE_METHOD(TrustchainFixture, "Alice's session can encrypt for Bob")
{
  auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession({bob.spublicIdentity()}));

  std::string const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData(encSess.encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(TC_AWAIT(encSess.encrypt(encryptedData, make_buffer(clearData))));

  REQUIRE_NOTHROW(TC_AWAIT(checkDecrypt({bobSession}, clearData, encryptedData)));
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can session-encrypt without sharing with self")
{
  auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession({bob.spublicIdentity()}, {}, Core::ShareWithSelf::No));

  std::string const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData(encSess.encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(TC_AWAIT(encSess.encrypt(encryptedData, make_buffer(clearData))));
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->decrypt(encryptedData)), Errc::InvalidArgument);
  REQUIRE_NOTHROW(TC_AWAIT(checkDecrypt({bobSession}, clearData, encryptedData)));
}

TEST_CASE_METHOD(TrustchainFixture, "Alice cannot session-encrypt without sharing with anybody")
{
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->makeEncryptionSession({}, {}, Core::ShareWithSelf::No)),
                                Errc::InvalidArgument);
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can session-encrypt a stream")
{
  auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession());

  auto const clearText = "my clear data is clear";
  auto const clearData = make_buffer(clearText);
  auto const [encryptorStream, resourceId] = encSess.makeEncryptionStream(Streams::bufferViewToInputSource(clearData));

  auto encryptedData = TC_AWAIT(Streams::readAllStream(encryptorStream));
  REQUIRE_NOTHROW(TC_AWAIT(checkDecrypt({aliceSession}, clearText, encryptedData)));
  CHECK(resourceId == encSess.resourceId());
  CHECK(Core::getResourceId(encryptedData) == ResourceId{encSess.resourceId()});
}

inline auto const sessionEncryptionOverhead = 57;
inline auto const paddedSessionEncryptionOverhead = sessionEncryptionOverhead + 1;

TEST_CASE_METHOD(TrustchainFixture, "Alice can use the padding option with an encryption session")
{
  SECTION("session encrypt/decrypt with auto padding")
  {
    auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession({}, {}, Core::ShareWithSelf::Yes, std::nullopt));

    auto const clearData = "my clear data is clear!"s;
    auto const lengthWithPadme = 24;
    std::vector<uint8_t> encryptedData(encSess.encryptedSize(clearData.size()));
    REQUIRE_NOTHROW(TC_AWAIT(encSess.encrypt(encryptedData, make_buffer(clearData))));

    CHECK(encryptedData.size() - paddedSessionEncryptionOverhead == lengthWithPadme);
    REQUIRE_NOTHROW(TC_AWAIT(checkDecrypt({aliceSession}, clearData, encryptedData)));
  }

  SECTION("session encrypt/decrypt with no padding")
  {
    auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession({}, {}, Core::ShareWithSelf::Yes, Padding::Off));

    auto const clearData = "my clear data is clear!"s;
    std::vector<uint8_t> encryptedData(encSess.encryptedSize(clearData.size()));
    REQUIRE_NOTHROW(TC_AWAIT(encSess.encrypt(encryptedData, make_buffer(clearData))));

    CHECK(encryptedData.size() - sessionEncryptionOverhead == clearData.size());
    REQUIRE_NOTHROW(TC_AWAIT(checkDecrypt({aliceSession}, clearData, encryptedData)));
  }

  SECTION("session encrypt/decrypt with a padding step")
  {
    auto const step = 13;
    auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession({}, {}, Core::ShareWithSelf::Yes, step));

    auto const clearData = "my clear data is clear!"s;
    std::vector<uint8_t> encryptedData(encSess.encryptedSize(clearData.size()));
    REQUIRE_NOTHROW(TC_AWAIT(encSess.encrypt(encryptedData, make_buffer(clearData))));

    CHECK((encryptedData.size() - paddedSessionEncryptionOverhead) % step == 0);
    REQUIRE_NOTHROW(TC_AWAIT(checkDecrypt({aliceSession}, clearData, encryptedData)));
  }

  SECTION(
      "session encrypt/decrypt with a huge padding step should select the v8 "
      "format")
  {
    auto const step = 2 * 1024 * 1024;
    auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession({}, {}, Core::ShareWithSelf::Yes, step));

    auto const clearData = "my clear data is clear!"s;
    std::vector<uint8_t> encryptedData(encSess.encryptedSize(clearData.size()));
    REQUIRE_NOTHROW(TC_AWAIT(encSess.encrypt(encryptedData, make_buffer(clearData))));

    CHECK(encryptedData[0] == 0x08);
    REQUIRE_NOTHROW(TC_AWAIT(checkDecrypt({aliceSession}, clearData, encryptedData)));
  }
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can session-encrypt/decrypt a huge buffer with auto padding")
{
  std::vector<uint8_t> clearData(almostFiveMiB);
  Crypto::randomFill(clearData);
  auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession({}, {}, Core::ShareWithSelf::Yes, std::nullopt));
  std::vector<uint8_t> encryptedData(encSess.encryptedSize(clearData.size()));
  TC_AWAIT(encSess.encrypt(encryptedData, clearData));
  CHECK(EncryptorV8::decryptedSize(encryptedData) == fiveMiB);
  auto decryptedData = TC_AWAIT(aliceSession->decrypt(encryptedData));

  CHECK(decryptedData == clearData);
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can session-encrypt/decrypt a huge buffer with no padding")
{
  std::vector<uint8_t> clearData(almostFiveMiB);
  Crypto::randomFill(clearData);
  auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession({}, {}, Core::ShareWithSelf::Yes, Padding::Off));
  std::vector<uint8_t> encryptedData(encSess.encryptedSize(clearData.size()));
  TC_AWAIT(encSess.encrypt(encryptedData, clearData));
  CHECK(EncryptorV4::decryptedSize(encryptedData) == almostFiveMiB);
  auto decryptedData = TC_AWAIT(aliceSession->decrypt(encryptedData));

  CHECK(decryptedData == clearData);
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can session-encrypt/decrypt a huge buffer with a padding of 500")
{
  std::vector<uint8_t> clearData(almostFiveMiB);
  Crypto::randomFill(clearData);
  auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession({}, {}, Core::ShareWithSelf::Yes, 500));
  std::vector<uint8_t> encryptedData(encSess.encryptedSize(clearData.size()));
  TC_AWAIT(encSess.encrypt(encryptedData, clearData));
  CHECK(EncryptorV8::decryptedSize(encryptedData) % 500 == 0);
  auto decryptedData = TC_AWAIT(aliceSession->decrypt(encryptedData));

  CHECK(decryptedData == clearData);
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can session-stream-encrypt with auto padding")
{
  std::vector<uint8_t> clearData(almostFiveMiB);
  Crypto::randomFill(clearData);
  auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession({}, {}, Core::ShareWithSelf::Yes, std::nullopt));
  auto [encryptorStream, encryptorResourceId] =
      encSess.makeEncryptionStream(Streams::bufferViewToInputSource(clearData));
  auto encryptedData = TC_AWAIT(Streams::readAllStream(encryptorStream));
  CHECK(EncryptorV8::decryptedSize(encryptedData) == fiveMiB);
  auto decryptedData = TC_AWAIT(aliceSession->decrypt(encryptedData));

  CHECK(Core::getResourceId(encryptedData) == ResourceId{encryptorResourceId});
  CHECK(decryptedData == clearData);
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can session-stream-encrypt with no padding")
{
  std::vector<uint8_t> clearData(almostFiveMiB);
  Crypto::randomFill(clearData);
  auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession({}, {}, Core::ShareWithSelf::Yes, Padding::Off));
  auto [encryptorStream, encryptorResourceId] =
      encSess.makeEncryptionStream(Streams::bufferViewToInputSource(clearData));
  auto encryptedData = TC_AWAIT(Streams::readAllStream(encryptorStream));
  CHECK(EncryptorV4::decryptedSize(encryptedData) == almostFiveMiB);
  auto decryptedData = TC_AWAIT(aliceSession->decrypt(encryptedData));

  CHECK(Core::getResourceId(encryptedData) == ResourceId{encryptorResourceId});
  CHECK(decryptedData == clearData);
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can session-stream-encrypt with a padding of 500")
{
  std::vector<uint8_t> clearData(almostFiveMiB);
  Crypto::randomFill(clearData);
  auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession({}, {}, Core::ShareWithSelf::Yes, 500));
  auto [encryptorStream, encryptorResourceId] =
      encSess.makeEncryptionStream(Streams::bufferViewToInputSource(clearData));
  auto encryptedData = TC_AWAIT(Streams::readAllStream(encryptorStream));
  CHECK(EncryptorV8::decryptedSize(encryptedData) % 500 == 0);
  auto decryptedData = TC_AWAIT(aliceSession->decrypt(encryptedData));

  CHECK(Core::getResourceId(encryptedData) == ResourceId{encryptorResourceId});
  CHECK(decryptedData == clearData);
}
