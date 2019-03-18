#include <Tanker/AsyncCore.hpp>
#include <Tanker/UserNotFound.hpp>

#include <Helpers/Buffers.hpp>

#include <doctest.h>

#include "CheckDecrypt.hpp"
#include "TrustchainFixture.hpp"

namespace Tanker
{

TEST_SUITE("Groups")
{

  TEST_CASE_FIXTURE(TrustchainFixture, "Alice can create a group with Bob")
  {
    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto aliceSession = TC_AWAIT(aliceDevice.open());

    auto bob = trustchain.makeUser();
    auto bobDevices = TC_AWAIT(bob.makeDevices(1));

    TC_AWAIT(aliceSession->syncTrustchain());

    REQUIRE_NOTHROW(TC_AWAIT(aliceSession->createGroup(
        {bob.spublicIdentity(), alice.spublicIdentity()})));
  }

  TEST_CASE_FIXTURE(TrustchainFixture, "Alice uses encrypt to share to a group")
  {
    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto aliceSession = TC_AWAIT(aliceDevice.open());

    auto bob = trustchain.makeUser();
    auto bobDevices = TC_AWAIT(bob.makeDevices(1));

    TC_AWAIT(aliceSession->syncTrustchain());

    auto myGroup = TC_AWAIT(aliceSession->createGroup({bob.spublicIdentity()}));

    auto const clearData = make_buffer("my clear data is clear");
    std::vector<uint8_t> encryptedData(
        AsyncCore::encryptedSize(clearData.size()));
    REQUIRE_NOTHROW(TC_AWAIT(
        aliceSession->encrypt(encryptedData.data(), clearData, {}, {myGroup})));

    REQUIRE(TC_AWAIT(
        checkDecrypt(bobDevices, {std::make_tuple(clearData, encryptedData)})));
  }

  TEST_CASE_FIXTURE(TrustchainFixture, "Alice encrypts and shares to a group")
  {
    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto aliceSession = TC_AWAIT(aliceDevice.open());

    auto bob = trustchain.makeUser();
    auto bobDevices = TC_AWAIT(bob.makeDevices(1));

    TC_AWAIT(aliceSession->syncTrustchain());

    auto myGroup = TC_AWAIT(aliceSession->createGroup({bob.spublicIdentity()}));

    auto const clearData = make_buffer("my clear data is clear");
    std::vector<uint8_t> encryptedData(
        AsyncCore::encryptedSize(clearData.size()));
    REQUIRE_NOTHROW(
        TC_AWAIT(aliceSession->encrypt(encryptedData.data(), clearData)));
    auto const resourceId = AsyncCore::getResourceId(encryptedData).get();
    REQUIRE_NOTHROW(TC_AWAIT(aliceSession->share({resourceId}, {}, {myGroup})));

    REQUIRE(TC_AWAIT(
        checkDecrypt(bobDevices, {std::make_tuple(clearData, encryptedData)})));
  }

  TEST_CASE_FIXTURE(TrustchainFixture, "Can add users to a group")
  {
    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto aliceSession = TC_AWAIT(aliceDevice.open());

    auto bob = trustchain.makeUser();
    auto bobDevices = TC_AWAIT(bob.makeDevices(1));

    auto const groupId =
        TC_AWAIT(aliceSession->createGroup({alice.spublicIdentity()}));

    REQUIRE_NOTHROW(TC_AWAIT(
        aliceSession->updateGroupMembers(groupId, {bob.spublicIdentity()})));
  }

  TEST_CASE_FIXTURE(TrustchainFixture, "Can transitively add users to a group")
  {
    auto Alice = trustchain.makeUser();
    auto Bob = trustchain.makeUser();
    auto Charlie = trustchain.makeUser();

    auto AliceDevice = Alice.makeDevice();
    auto BobDevice = Bob.makeDevice();
    auto CharlieDevice = Charlie.makeDevice();

    auto const clearData = make_buffer("my clear data is clear");
    std::vector<uint8_t> encryptedData(
        AsyncCore::encryptedSize(clearData.size()));
    {
      auto AliceSession = TC_AWAIT(AliceDevice.open());
      auto BobSession = TC_AWAIT(BobDevice.open());
      auto CharlieSession = TC_AWAIT(CharlieDevice.open());

      auto const groupId =
          TC_AWAIT(AliceSession->createGroup({Bob.spublicIdentity()}));
      TC_AWAIT(
          BobSession->updateGroupMembers(groupId, {Charlie.spublicIdentity()}));
      TC_AWAIT(CharlieSession->updateGroupMembers(groupId,
                                                  {Alice.spublicIdentity()}));

      REQUIRE_NOTHROW(TC_AWAIT(CharlieSession->encrypt(
          encryptedData.data(), clearData, {}, {groupId})));
    }

    REQUIRE(TC_AWAIT(checkDecrypt(
        {AliceDevice}, {std::make_tuple(clearData, encryptedData)})));
  }
}
}
