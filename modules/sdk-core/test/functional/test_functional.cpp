#include <string>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/RecipientNotFound.hpp>
#include <Tanker/ResourceKeyNotFound.hpp>
#include <Tanker/SdkInfo.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Types/SUserId.hpp>

#include <Tanker/Test/Functional/TrustchainFixture.hpp>

#include <doctest.h>

#include <Helpers/Buffers.hpp>
#include <Helpers/SignalSpy.hpp>
#include <Helpers/UniquePath.hpp>

#include "CheckDecrypt.hpp"

#include <tconcurrent/async_wait.hpp>

using namespace std::string_literals;

using namespace Tanker;
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
  REQUIRE(core->isOpen());
  SignalSpy<void> spyClose(core->sessionClosed());
  TC_AWAIT(core->signOut());
  REQUIRE(!core->isOpen());
  REQUIRE(spyClose.receivedEvents.size() == 1);
}

TEST_CASE_FIXTURE(TrustchainFixture, "it can open/close a session twice")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();
  auto core = TC_AWAIT(device.open());
  REQUIRE(core->isOpen());
  SignalSpy<void> spyClose(core->sessionClosed());
  TC_AWAIT(core->signOut());
  REQUIRE(!core->isOpen());
  REQUIRE(spyClose.receivedEvents.size() == 1);
  core = TC_AWAIT(device.open());
  REQUIRE(core->isOpen());
  TC_AWAIT(core->signOut());
  REQUIRE(!core->isOpen());
  REQUIRE(spyClose.receivedEvents.size() == 2);
}

TEST_CASE_FIXTURE(TrustchainFixture, "it can reopen a closed session")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();

  auto const core = TC_AWAIT(device.open());
  TC_AWAIT(core->signOut());
  REQUIRE(!core->isOpen());
  TC_AWAIT(core->signIn(alice.identity));
  REQUIRE(core->isOpen());
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "it should prevent opening the same device twice")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();

  auto const core = TC_AWAIT(device.open());

  auto const core2 = device.createCore(Test::SessionType::New);
  REQUIRE_THROWS(TC_AWAIT(core2->signIn(alice.identity)));
}

TEST_CASE_FIXTURE(TrustchainFixture, "it can open a session on a second device")
{
  auto alice = trustchain.makeUser();

  auto device1 = alice.makeDevice();
  auto session = TC_AWAIT(device1.open());
  auto device2 = alice.makeDevice(Test::DeviceType::New);
  REQUIRE_NOTHROW(TC_AWAIT(device2.attachDevice(*session)));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "it fails to signUp if the user already exists")
{
  auto alice = trustchain.makeUser(Test::UserType::New);
  auto device1 = alice.makeDevice();
  {
    auto session = TC_AWAIT(device1.open(Test::SessionType::New));
  }
  auto session = device1.createCore(Test::SessionType::New);
  REQUIRE_THROWS_AS(TC_AWAIT(session->signUp(alice.identity)),
                    Error::IdentityAlreadyRegistered);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "it fails to open if no sign in options are provided")
{
  auto alice = trustchain.makeUser();
  auto device1 = alice.makeDevice();
  auto device2 = alice.makeDevice(Test::DeviceType::New);
  auto session = TC_AWAIT(device1.open());
  auto tanker2 = device2.createCore(Test::SessionType::New);
  REQUIRE_EQ(TC_AWAIT(tanker2->signIn(alice.identity)),
             OpenResult::IdentityVerificationNeeded);
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
  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->encrypt(
      encryptedData.data(), clearData, {bob.spublicIdentity()})));

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
  TC_AWAIT(aliceSession->signOut());
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

  TC_AWAIT(aliceSecondSession->signOut());

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
      TC_AWAIT(bobSession->decrypt(decryptedData.data(), encryptedData)),
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
      TC_AWAIT(aliceSession->share(resourceIds, {bob.spublicIdentity()}, {})));
  REQUIRE(TC_AWAIT(checkDecrypt(bobDevice, metaResources)));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Alice can encrypt and share to a provisional user")
{
  auto const bobEmail = Email{"bob@my-box-of-emai.ls"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      cppcodec::base64_rfc4648::encode(trustchain.id), bobEmail);

  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData(
      AsyncCore::encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->encrypt(
      encryptedData.data(),
      clearData,
      {SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentity)}})));

  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto bobSession = TC_AWAIT(bobDevice.open());

  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));

  TC_AWAIT(bobSession->claimProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity},
      VerificationCode{bobVerificationCode}));

  std::vector<uint8_t> decrypted(
      bobSession->decryptedSize(encryptedData).get());
  TC_AWAIT(bobSession->decrypt(decrypted.data(), encryptedData));
  CHECK(decrypted == clearData);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Handles incorrect verification codes when claiming")
{
  auto const bobEmail = Email{"bob@my-box-of-emai.ls"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      cppcodec::base64_rfc4648::encode(trustchain.id), bobEmail);

  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto bobSession = TC_AWAIT(bobDevice.open());

  auto const bobVerificationCode = VerificationCode{"invalid"};

  CHECK_THROWS_AS(TC_AWAIT(bobSession->claimProvisionalIdentity(
                      SSecretProvisionalIdentity{bobProvisionalIdentity},
                      VerificationCode{bobVerificationCode})),
                  Error::InvalidVerificationCode);
}

TEST_CASE_FIXTURE(TrustchainFixture, "Alice can revoke a device")
{
  auto alice = trustchain.makeUser(Test::UserType::New);
  auto aliceDevice = alice.makeDevice();
  auto const aliceSession = TC_AWAIT(aliceDevice.open());

  auto const deviceId = aliceSession->deviceId().get();

  tc::promise<void> prom;
  aliceSession->deviceRevoked().connect([&] { prom.set_value({}); });

  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->revokeDevice(deviceId)));

  TC_AWAIT(waitForPromise(prom));

  CHECK(!aliceSession->isOpen());
  auto core = aliceDevice.createCore(Test::SessionType::Cached);

  CHECK_EQ(TC_AWAIT(core->signIn(aliceDevice.identity())),
           OpenResult::IdentityVerificationNeeded);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Alice can revoke a device while it is disconnected")
{
  auto alice = trustchain.makeUser(Test::UserType::New);
  auto aliceDevice = alice.makeDevice();
  auto const aliceSession = TC_AWAIT(aliceDevice.open());

  auto const deviceId = TC_AWAIT(aliceSession->deviceId());

  auto aliceDevice2 = alice.makeDevice();
  auto const aliceSession2 = TC_AWAIT(aliceDevice2.open(*aliceSession));

  TC_AWAIT(aliceSession->signOut());

  REQUIRE_NOTHROW(TC_AWAIT(aliceSession2->revokeDevice(deviceId)));

  tc::promise<void> prom;
  aliceSession->deviceRevoked().connect([&] { prom.set_value({}); });

  CHECK_THROWS_AS(TC_AWAIT(aliceSession->signIn(aliceDevice.identity())),
                  Error::OperationCanceled);

  TC_AWAIT(waitForPromise(prom));
}

TEST_CASE_FIXTURE(TrustchainFixture, "Alice can revokes a device and opens it")
{
  auto alice = trustchain.makeUser(Test::UserType::New);
  auto aliceDevice = alice.makeDevice();

  {
    auto const aliceSession = TC_AWAIT(aliceDevice.open());
    auto const deviceId = TC_AWAIT(aliceSession->deviceId());
    REQUIRE_NOTHROW(TC_AWAIT(aliceSession->revokeDevice(deviceId)));
    TC_AWAIT(aliceSession->signOut());
  }

  try
  {
    auto const aliceSession = aliceDevice.createCore(Test::SessionType::New);
    auto const result = TC_AWAIT(aliceSession->signIn(aliceDevice.identity()));
    // the revocation was handled before the session was closed
    CHECK(result == OpenResult::IdentityVerificationNeeded);
  }
  catch (Error::OperationCanceled const&)
  {
    // the revocation was handled during the open()
    CHECK(true);
  }
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Alice can reopen and decrypt with a revoked device")
{
  auto alice = trustchain.makeUser(Test::UserType::New);
  auto aliceDevice = alice.makeDevice();
  auto const aliceSession = TC_AWAIT(aliceDevice.open());

  auto aliceSecondDevice = alice.makeDevice();
  auto otherSession = TC_AWAIT(aliceSecondDevice.open(*aliceSession));

  auto const deviceId = otherSession->deviceId().get();

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

  CHECK(!otherSession->isOpen());

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

  auto const deviceId = aliceSession->deviceId().get();

  auto aliceSecondDevice = alice.makeDevice();
  auto const otherSession = TC_AWAIT(aliceSecondDevice.open(*aliceSession));
  auto const otherDeviceId = otherSession->deviceId().get();

  tc::promise<void> prom;
  otherSession->deviceRevoked().connect([&] { prom.set_value({}); });

  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->revokeDevice(otherDeviceId)));

  TC_AWAIT(waitForPromise(prom));

  CHECK(!otherSession->isOpen());

  {
    auto core = aliceSecondDevice.createCore(Test::SessionType::Cached);

    CHECK_EQ(TC_AWAIT(core->signIn(aliceSecondDevice.identity())),
             OpenResult::IdentityVerificationNeeded);
  }

  tc::promise<void> prom2;
  aliceSession->deviceRevoked().connect([&] { prom2.set_value({}); });

  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->revokeDevice(deviceId)));

  TC_AWAIT(waitForPromise(prom2));

  CHECK(!aliceSession->isOpen());

  auto core = aliceDevice.createCore(Test::SessionType::Cached);

  CHECK_EQ(TC_AWAIT(core->signIn(aliceDevice.identity())),
           OpenResult::IdentityVerificationNeeded);
}
