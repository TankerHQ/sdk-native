#include <Tanker/Functional/TrustchainFixture.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Errors/Errc.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include <doctest.h>

#include "CheckDecrypt.hpp"

using namespace Tanker;
using Tanker::Functional::TrustchainFixture;

TEST_SUITE("Encryption sessions")
{
  TEST_CASE_FIXTURE(TrustchainFixture, "Alice can create a session with Bob")
  {
    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto aliceSession = TC_AWAIT(aliceDevice.open());

    auto bob = trustchain.makeUser();
    auto bobDevices = TC_AWAIT(bob.makeDevices(1));

    REQUIRE_NOTHROW(TC_AWAIT(aliceSession->makeEncryptionSession(
        {bob.spublicIdentity(), alice.spublicIdentity()})));
  }

  TEST_CASE_FIXTURE(TrustchainFixture,
                    "Alice's session can encrypt for herself")
  {
    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto aliceSession = TC_AWAIT(aliceDevice.open());

    auto encSessPtr =
        TC_AWAIT(aliceSession->makeEncryptionSession());
    auto encSess = std::unique_ptr<EncryptionSession>(encSessPtr);

    auto const clearData = make_buffer("my clear data is clear");
    std::vector<uint8_t> encryptedData(
        EncryptionSession::encryptedSize(clearData.size()));
    REQUIRE_NOTHROW(
        TC_AWAIT(encSess->encrypt(encryptedData.data(), clearData)));

    REQUIRE(TC_AWAIT(checkDecrypt(
        {aliceDevice}, {std::make_tuple(clearData, encryptedData)})));
  }

  TEST_CASE_FIXTURE(TrustchainFixture, "Alice's session can encrypt for Bob")
  {
    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto aliceSession = TC_AWAIT(aliceDevice.open());

    auto bob = trustchain.makeUser();
    auto bobDevices = TC_AWAIT(bob.makeDevices(1));

    auto encSessPtr =
        TC_AWAIT(aliceSession->makeEncryptionSession({bob.spublicIdentity()}));
    auto encSess = std::unique_ptr<EncryptionSession>(encSessPtr);

    auto const clearData = make_buffer("my clear data is clear");
    std::vector<uint8_t> encryptedData(
        EncryptionSession::encryptedSize(clearData.size()));
    REQUIRE_NOTHROW(
        TC_AWAIT(encSess->encrypt(encryptedData.data(), clearData)));

    REQUIRE(TC_AWAIT(
        checkDecrypt(bobDevices, {std::make_tuple(clearData, encryptedData)})));
  }
}
