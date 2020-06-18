#include <Tanker/Functional/TrustchainFixture.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Errors/Errc.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include <doctest/doctest.h>

#include "CheckDecrypt.hpp"

using namespace Tanker;
using namespace Tanker::Errors;
using Tanker::Functional::TrustchainFixture;

TEST_SUITE_BEGIN("Encryption sessions");

TEST_CASE_FIXTURE(TrustchainFixture, "Alice's session can encrypt for herself")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData(
      EncryptionSession::encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(TC_AWAIT(encSess.encrypt(encryptedData.data(), clearData)));

  REQUIRE(TC_AWAIT(checkDecrypt({aliceDevice}, {{clearData, encryptedData}})));
}

TEST_CASE_FIXTURE(TrustchainFixture, "Alice's session can encrypt for Bob")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto bob = trustchain.makeUser();
  auto bobDevices = TC_AWAIT(bob.makeDevices(1));

  auto encSess =
      TC_AWAIT(aliceSession->makeEncryptionSession({bob.spublicIdentity()}));

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData(
      EncryptionSession::encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(TC_AWAIT(encSess.encrypt(encryptedData.data(), clearData)));

  REQUIRE(TC_AWAIT(
      checkDecrypt(bobDevices, {std::make_tuple(clearData, encryptedData)})));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Alice can session-encrypt without sharing with self")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());
  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto bobSession = TC_AWAIT(bobDevice.open());

  auto encSess = TC_AWAIT(aliceSession->makeEncryptionSession(
      {bob.spublicIdentity()}, {}, Core::ShareWithSelf::No));

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData(
      EncryptionSession::encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(TC_AWAIT(encSess.encrypt(encryptedData.data(), clearData)));
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->decrypt(encryptedData)),
                                Errc::InvalidArgument);
  REQUIRE_NOTHROW(TC_AWAIT(bobSession->decrypt(encryptedData)));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Alice cannot stream-encrypt without sharing with anybody")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->makeEncryptionSession(
                                    {}, {}, Core::ShareWithSelf::No)),
                                Errc::InvalidArgument);
}

TEST_SUITE_END();
