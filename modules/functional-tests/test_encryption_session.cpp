#include <Tanker/Functional/TrustchainFixture.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Errors/Errc.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include "TestSuite.hpp"

#include "CheckDecrypt.hpp"

using namespace Tanker;
using namespace Tanker::Errors;
using Tanker::Functional::TrustchainFixture;

namespace
{
constexpr auto fiveMiB = 5 * 1024 * 1024;
}

TEST_CASE_METHOD(TrustchainFixture, "Alice's session can encrypt for herself")
{
  auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession());

  std::string const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData(
      EncryptionSession::encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(
      TC_AWAIT(encSess.encrypt(encryptedData, make_buffer(clearData))));

  REQUIRE_NOTHROW(
      TC_AWAIT(checkDecrypt({aliceSession}, clearData, encryptedData)));
  CHECK(Core::getResourceId(encryptedData) == encSess.resourceId());
}

TEST_CASE_METHOD(TrustchainFixture,
                 "Alice's session can encrypt a huge resource")
{
  auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession());

  std::string clearData(fiveMiB, 42);
  std::vector<uint8_t> encryptedData(
      EncryptionSession::encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(
      TC_AWAIT(encSess.encrypt(encryptedData, make_buffer(clearData))));

  REQUIRE_NOTHROW(
      TC_AWAIT(checkDecrypt({aliceSession}, clearData, encryptedData)));
  CHECK(Core::getResourceId(encryptedData) == encSess.resourceId());
}

TEST_CASE_METHOD(TrustchainFixture, "Alice's session can encrypt for Bob")
{
  auto encSess =
      TC_AWAIT(aliceSession->makeEncryptionSession({bob.spublicIdentity()}));

  std::string const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData(
      EncryptionSession::encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(
      TC_AWAIT(encSess.encrypt(encryptedData, make_buffer(clearData))));

  REQUIRE_NOTHROW(
      TC_AWAIT(checkDecrypt({bobSession}, clearData, encryptedData)));
}

TEST_CASE_METHOD(TrustchainFixture,
                 "Alice can session-encrypt without sharing with self")
{
  auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession(
      {bob.spublicIdentity()}, {}, Core::ShareWithSelf::No));

  std::string const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData(
      EncryptionSession::encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(
      TC_AWAIT(encSess.encrypt(encryptedData, make_buffer(clearData))));
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

TEST_CASE_METHOD(TrustchainFixture, "Alice can session-encrypt a stream")
{
  auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession());

  auto const clearText = "my clear data is clear";
  auto const clearData = make_buffer(clearText);
  auto const [encryptorStream, resourceId] =
      encSess.makeEncryptionStream(Streams::bufferViewToInputSource(clearData));

  auto encryptedData = TC_AWAIT(Streams::readAllStream(encryptorStream));
  REQUIRE_NOTHROW(
      TC_AWAIT(checkDecrypt({aliceSession}, clearText, encryptedData)));
  CHECK(resourceId == encSess.resourceId());
  CHECK(Core::getResourceId(encryptedData) == encSess.resourceId());
}
