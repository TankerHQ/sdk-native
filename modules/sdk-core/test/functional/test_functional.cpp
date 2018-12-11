#include <string>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/RecipientNotFound.hpp>
#include <Tanker/SdkInfo.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Types/SUserId.hpp>

#include <Tanker/Test/Functional/Trustchain.hpp>

#include <doctest.h>

#include <Helpers/Buffers.hpp>
#include <Helpers/SignalSpy.hpp>
#include <Helpers/UniquePath.hpp>

#include "CheckDecrypt.hpp"
#include "TrustchainFixture.hpp"

#include <tconcurrent/async_wait.hpp>

using namespace std::string_literals;

namespace Tanker
{
using namespace type_literals;

namespace
{
auto make_clear_data(std::initializer_list<std::string> clearText)
{
  std::vector<std::vector<uint8_t>> clearDatas;
  std::transform(begin(clearText),
                 end(clearText),
                 std::back_inserter(clearDatas),
                 [](auto&& clear) { return make_buffer(clear); });
  return clearDatas;
}

tc::cotask<void> waitForPromise(tc::promise<void> prom)
{
  std::vector<tc::future<void>> futures;
  futures.push_back(prom.get_future());
  futures.push_back(tc::async_wait(std::chrono::seconds(2)));
  auto const result =
      TC_AWAIT(tc::when_any(std::make_move_iterator(futures.begin()),
                            std::make_move_iterator(futures.end()),
                            tc::when_any_options::auto_cancel));
  CHECK(result.index == 0);
}
}

TEST_CASE_FIXTURE(TrustchainFixture, "it can open/close a session")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();
  auto const core = TC_AWAIT(device.open());
  REQUIRE(core->status() == Status::Open);
  SignalSpy<void> spyClose(core->sessionClosed());
  TC_AWAIT(core->close());
  REQUIRE(core->status() == Status::Closed);
  REQUIRE(spyClose.receivedEvents.size() == 1);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "it fails to open when wrong userId/userToken is provided")
{
  auto alice = trustchain.makeUser();
  UniquePath p{"testtmp"};

  AsyncCore tanker(
      trustchain.url(), {"test", trustchain.id(), "0.0.1"}, p.path.string());

  REQUIRE_THROWS(TC_AWAIT(
      tanker.open("alice"_uid,
                  UserToken::generateUserToken(
                      base64::encode(trustchain.id()),
                      base64::encode(trustchain.signatureKeys().privateKey),
                      "bob"_uid))));
  REQUIRE_NOTHROW(TC_AWAIT(tanker.close()));
}

TEST_CASE_FIXTURE(TrustchainFixture, "it can reopen a closed session")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();

  auto const core = TC_AWAIT(device.open());
  TC_AWAIT(core->close());
  REQUIRE(core->status() == Status::Closed);
  TC_AWAIT(core->open(alice.suserId(), alice.userToken()));
  REQUIRE(core->status() == Status::Open);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "it should prevent opening the same device twice")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();

  auto const core = TC_AWAIT(device.open());

  auto const core2 = device.createCore(Test::SessionType::New);
  REQUIRE_THROWS(TC_AWAIT(core2->open(alice.suserId(), alice.userToken())));
}

TEST_CASE_FIXTURE(TrustchainFixture, "it can open a session on a second device")
{
  auto alice = trustchain.makeUser();

  auto device1 = alice.makeDevice();
  auto session = TC_AWAIT(device1.open());
  SignalSpy<void> deviceCreatedSpy(session->deviceCreated());
  auto device2 = alice.makeDevice(Test::DeviceType::New);
  REQUIRE_NOTHROW(TC_AWAIT(device2.attachDevice(*session)));
  CHECK(deviceCreatedSpy.receivedEvents.size() == 1);
}

TEST_CASE_FIXTURE(
    TrustchainFixture,
    "it fails to open if no device validation handler is registered")
{
  auto alice = trustchain.makeUser();
  auto device1 = alice.makeDevice();
  auto device2 = alice.makeDevice(Test::DeviceType::New);
  auto session = TC_AWAIT(device1.open());
  auto tanker2 = device2.createCore(Test::SessionType::New);
  REQUIRE_THROWS_AS(TC_AWAIT(tanker2->open(alice.suserId(), alice.userToken())),
                    Error::InvalidUnlockEventHandler);
}

TEST_CASE_FIXTURE(TrustchainFixture, "It can encrypt/decrypt")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  TC_AWAIT(aliceSession->syncTrustchain());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData(
      AsyncCore::encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(
      TC_AWAIT(aliceSession->encrypt(encryptedData.data(), clearData)));
  std::vector<uint8_t> decryptedData(
      AsyncCore::decryptedSize(encryptedData).get());
  REQUIRE_NOTHROW(
      TC_AWAIT(aliceSession->decrypt(decryptedData.data(), encryptedData)));

  REQUIRE_EQ(decryptedData, clearData);
}

TEST_CASE_FIXTURE(TrustchainFixture, "Alice encrypt and share to Bob")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto bob = trustchain.makeUser();
  auto bobDevices = TC_AWAIT(bob.makeDevices(2));

  TC_AWAIT(aliceSession->syncTrustchain());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData(
      AsyncCore::encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(TC_AWAIT(
      aliceSession->encrypt(encryptedData.data(), clearData, {bob.suserId()})));

  REQUIRE(TC_AWAIT(
      checkDecrypt(bobDevices, {std::make_tuple(clearData, encryptedData)})));
}

TEST_CASE_FIXTURE(TrustchainFixture, "Alice shares to all her devices")
{
  auto alice = trustchain.makeUser();
  auto aliceDevices = TC_AWAIT(alice.makeDevices(3));
  auto const aliceSession = TC_AWAIT(aliceDevices[0].open());

  TC_AWAIT(aliceSession->syncTrustchain());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData(
      AsyncCore::encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(
      TC_AWAIT(aliceSession->encrypt(encryptedData.data(), clearData)));
  TC_AWAIT(aliceSession->close());
  REQUIRE(TC_AWAIT(
      checkDecrypt(aliceDevices, {std::make_tuple(clearData, encryptedData)})));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Alice's second device can decrypt old resources")
{
  auto alice = trustchain.makeUser();
  auto aliceFirstDevice = alice.makeDevice();
  auto const aliceFirstSession = TC_AWAIT(aliceFirstDevice.open());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData(
      AsyncCore::encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(
      TC_AWAIT(aliceFirstSession->encrypt(encryptedData.data(), clearData)));

  auto aliceSecondDevice = alice.makeDevice();
  auto const aliceSecondSession =
      TC_AWAIT(aliceSecondDevice.open(*aliceFirstSession));

  TC_AWAIT(aliceSecondSession->close());

  REQUIRE_UNARY(TC_AWAIT(checkDecrypt(
      {aliceSecondDevice}, {std::make_tuple(clearData, encryptedData)})));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Bob will timeout when trying to decrypt without the key")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto bobSession = TC_AWAIT(bobDevice.open());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData(
      AsyncCore::encryptedSize(clearData.size()));
  TC_AWAIT(aliceSession->encrypt(encryptedData.data(), clearData));

  auto const resourceId = AsyncCore::getResourceId(encryptedData).get();

  std::vector<uint8_t> decryptedData;
  decryptedData.resize(clearData.size());

  CHECK_THROWS_AS(
      TC_AWAIT(bobSession->decrypt(
          decryptedData.data(), encryptedData, std::chrono::milliseconds(500))),
      Error::ResourceKeyNotFound);
}

TEST_CASE_FIXTURE(TrustchainFixture, "Alice can share many resources to Bob")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto bob = trustchain.makeUser();
  auto bobDevice = TC_AWAIT(bob.makeDevices(1));

  TC_AWAIT(aliceSession->syncTrustchain());

  auto const clearDatas = make_clear_data(
      {"to be clear, ", "or not be clear, ", "that is the test case..."});

  std::vector<std::tuple<std::vector<uint8_t>, std::vector<uint8_t>>>
      metaResources;
  metaResources.reserve(clearDatas.size());
  std::vector<SResourceId> resourceIds;
  resourceIds.reserve(clearDatas.size());
  for (auto const& clearData : clearDatas)
  {
    std::vector<uint8_t> encryptedData(
        AsyncCore::encryptedSize(clearData.size()));
    TC_AWAIT(aliceSession->encrypt(encryptedData.data(), clearData));
    resourceIds.emplace_back(AsyncCore::getResourceId(encryptedData).get());
    metaResources.emplace_back(std::move(clearData), std::move(encryptedData));
  }

  REQUIRE_NOTHROW(
      TC_AWAIT(aliceSession->share(resourceIds, {bob.suserId()}, {})));
  REQUIRE(TC_AWAIT(checkDecrypt(bobDevice, metaResources)));
}

TEST_CASE_FIXTURE(TrustchainFixture, "Alice can revoke a device")
{
  auto alice = trustchain.makeUser(Test::UserType::New);
  auto aliceDevice = alice.makeDevice();
  auto const aliceSession = TC_AWAIT(aliceDevice.open());

  auto const deviceId = TC_AWAIT(aliceSession->deviceId());

  tc::promise<void> prom;
  aliceSession->deviceRevoked().connect([&] { prom.set_value({}); });

  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->revokeDevice(deviceId)));

  TC_AWAIT(waitForPromise(prom));

  CHECK(aliceSession->status() == Status::Closed);

  CHECK_THROWS_AS(TC_AWAIT(aliceDevice.open()),
                  Error::InvalidUnlockEventHandler);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Alice can reopen and decrypt with a revoked device")
{
  auto alice = trustchain.makeUser(Test::UserType::New);
  auto aliceDevice = alice.makeDevice();
  auto const aliceSession = TC_AWAIT(aliceDevice.open());

  auto aliceSecondDevice = alice.makeDevice();
  auto otherSession = TC_AWAIT(aliceSecondDevice.open(*aliceSession));

  auto const deviceId = TC_AWAIT(otherSession->deviceId());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData(
      AsyncCore::encryptedSize(clearData.size()));
  TC_AWAIT(otherSession->encrypt(encryptedData.data(), clearData));

  std::vector<uint8_t> decryptedData;
  decryptedData.resize(clearData.size());

  tc::promise<void> prom;
  otherSession->deviceRevoked().connect([&] { prom.set_value({}); });

  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->revokeDevice(deviceId)));

  TC_AWAIT(waitForPromise(prom));

  CHECK(otherSession->status() == Status::Closed);

  TC_AWAIT(aliceSecondDevice.open(*aliceSession));
  REQUIRE_UNARY(TC_AWAIT(checkDecrypt(
      {aliceSecondDevice}, {std::make_tuple(clearData, encryptedData)})));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "multiple devices can be successively revoked")
{
  auto alice = trustchain.makeUser(Test::UserType::New);
  auto aliceDevice = alice.makeDevice();
  auto const aliceSession = TC_AWAIT(aliceDevice.open());

  auto const deviceId = TC_AWAIT(aliceSession->deviceId());

  auto aliceSecondDevice = alice.makeDevice();
  auto const otherSession = TC_AWAIT(aliceSecondDevice.open(*aliceSession));
  auto const otherDeviceId = TC_AWAIT(otherSession->deviceId());

  tc::promise<void> prom;
  otherSession->deviceRevoked().connect([&] { prom.set_value({}); });

  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->revokeDevice(otherDeviceId)));

  TC_AWAIT(waitForPromise(prom));

  CHECK(otherSession->status() == Status::Closed);

  CHECK_THROWS_AS(TC_AWAIT(aliceSecondDevice.open()),
                  Error::InvalidUnlockEventHandler);

  tc::promise<void> prom2;
  aliceSession->deviceRevoked().connect([&] { prom2.set_value({}); });

  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->revokeDevice(deviceId)));

  TC_AWAIT(waitForPromise(prom2));

  CHECK(aliceSession->status() == Status::Closed);

  CHECK_THROWS_AS(TC_AWAIT(aliceDevice.open()),
                  Error::InvalidUnlockEventHandler);
}
}
