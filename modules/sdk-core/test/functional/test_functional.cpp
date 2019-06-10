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

tc::cotask<bool> waitFor(tc::promise<void> prom)
{
  std::vector<tc::future<void>> futures;
  futures.push_back(prom.get_future());
  futures.push_back(tc::async_wait(std::chrono::seconds(2)));
  auto const result =
      TC_AWAIT(tc::when_any(std::make_move_iterator(futures.begin()),
                            std::make_move_iterator(futures.end()),
                            tc::when_any_options::auto_cancel));
  TC_RETURN(result.index == 0);
}

template <typename T /*, typename ...Args */>
class SpyEvent
{
  using ConnectHandler = void (T::*)(std::function<void()>);
  using DisconnectHandler = void (T::*)();

public:
  SpyEvent(T* target, ConnectHandler connect, DisconnectHandler disconnect)
    : target(target), connect(connect), disconnect(disconnect)
  {
    (target->*connect)([this]() { receivedEvents.emplace_back(0); });
  }

  ~SpyEvent()
  {
    (target->*disconnect)();
  }

  T* target;
  ConnectHandler connect;
  DisconnectHandler disconnect;
  std::vector<int> receivedEvents;
};
}

TEST_CASE_FIXTURE(TrustchainFixture, "it can open/close a session")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();
  auto const core = TC_AWAIT(device.open());
  REQUIRE(core->status() == Status::Ready);
  SpyEvent<AsyncCore> spyClose(core.get(),
                               &AsyncCore::connectSessionClosed,
                               &AsyncCore::disconnectSessionClosed);
  TC_AWAIT(core->stop());
  REQUIRE(core->status() == Status::Stopped);
  REQUIRE(spyClose.receivedEvents.size() == 1);
}

TEST_CASE_FIXTURE(TrustchainFixture, "it can open/close a session twice")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();
  auto core = TC_AWAIT(device.open());
  REQUIRE(core->status() == Status::Ready);
  SpyEvent<AsyncCore> spyClose(core.get(),
                               &AsyncCore::connectSessionClosed,
                               &AsyncCore::disconnectSessionClosed);
  TC_AWAIT(core->stop());
  REQUIRE(core->status() == Status::Stopped);
  REQUIRE(spyClose.receivedEvents.size() == 1);
  core = TC_AWAIT(device.open());
  REQUIRE(core->status() == Status::Ready);
  TC_AWAIT(core->stop());
  REQUIRE(core->status() == Status::Stopped);
  REQUIRE(spyClose.receivedEvents.size() == 2);
}

TEST_CASE_FIXTURE(TrustchainFixture, "it can reopen a closed session")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();

  auto const core = TC_AWAIT(device.open());
  TC_AWAIT(core->stop());
  REQUIRE(core->status() == Status::Stopped);
  CHECK_EQ(TC_AWAIT(core->start(alice.identity)), Status::Ready);
  CHECK_EQ(core->status(), Status::Ready);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "it should prevent opening the same device twice")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();

  auto const core = TC_AWAIT(device.open());

  auto const core2 = device.createCore(Test::SessionType::New);
  REQUIRE_THROWS(TC_AWAIT(core2->start(alice.identity)));
}

TEST_CASE_FIXTURE(TrustchainFixture, "it can open a session on a second device")
{
  auto alice = trustchain.makeUser();

  auto device1 = alice.makeDevice();
  auto session = TC_AWAIT(device1.open());
  auto device2 = alice.makeDevice(Test::DeviceType::New);
  REQUIRE_NOTHROW(TC_AWAIT(device2.open()));
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

TEST_CASE_FIXTURE(TrustchainFixture, "Alice encrypt and share with Bob")
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

TEST_CASE_FIXTURE(TrustchainFixture, "Alice shares with all her devices")
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
  TC_AWAIT(aliceSession->stop());
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
  auto const aliceSecondSession = TC_AWAIT(aliceSecondDevice.open());

  TC_AWAIT(aliceSecondSession->stop());

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

TEST_CASE_FIXTURE(TrustchainFixture, "Alice can share many resources with Bob")
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
                  "Alice can encrypt and share with a provisional user")
{
  auto const bobEmail = Email{"bob@mail.com"};
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

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  CHECK(result.status == Status::IdentityVerificationNeeded);
  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));

  TC_AWAIT(bobSession->verifyProvisionalIdentity(Unlock::EmailVerification{
      bobEmail, VerificationCode{bobVerificationCode}}));

  std::vector<uint8_t> decrypted(
      bobSession->decryptedSize(encryptedData).get());
  TC_AWAIT(bobSession->decrypt(decrypted.data(), encryptedData));
  CHECK(decrypted == clearData);
}

TEST_CASE_FIXTURE(
    TrustchainFixture,
    "Handles incorrect verification codes when verifying provisional identity")
{
  auto const bobEmail = Email{"bob2@mail.com"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      cppcodec::base64_rfc4648::encode(trustchain.id), bobEmail);

  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto bobSession = TC_AWAIT(bobDevice.open());

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  REQUIRE(result.status == Status::IdentityVerificationNeeded);
  auto const bobVerificationCode = VerificationCode{"invalid"};

  CHECK_THROWS_AS(
      TC_AWAIT(bobSession->verifyProvisionalIdentity(Unlock::EmailVerification{
          bobEmail, VerificationCode{bobVerificationCode}})),
      Error::InvalidVerificationCode);
}

TEST_CASE_FIXTURE(
    TrustchainFixture,
    "Bob claims a provisionalIdentity with an already verified email")
{
  auto const bobEmail = Email{"bob3@mail.com"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      cppcodec::base64_rfc4648::encode(trustchain.id), bobEmail);
  auto const bobOtherProvisionalIdentity = Identity::createProvisionalIdentity(
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
      {SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentity)},
       SPublicIdentity{
           Identity::getPublicIdentity(bobOtherProvisionalIdentity)}})));

  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto bobSession = TC_AWAIT(bobDevice.open());

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  REQUIRE(result.status == Status::IdentityVerificationNeeded);
  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
  TC_AWAIT(bobSession->verifyProvisionalIdentity(Unlock::EmailVerification{
      bobEmail, VerificationCode{bobVerificationCode}}));

  CHECK(TC_AWAIT(bobSession->attachProvisionalIdentity(
                     SSecretProvisionalIdentity{bobOtherProvisionalIdentity}))
            .status == Status::Ready);
}

TEST_CASE_FIXTURE(
    TrustchainFixture,
    "Bob cannot verify a provisionalIdentity without attaching it first")
{
  auto const bobEmail = Email{"bob4@mail.com"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      cppcodec::base64_rfc4648::encode(trustchain.id), bobEmail);

  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto bobSession = TC_AWAIT(bobDevice.open());
  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));

  CHECK_THROWS_AS(
      TC_AWAIT(bobSession->verifyProvisionalIdentity(Unlock::EmailVerification{
          bobEmail, VerificationCode{bobVerificationCode}})),
      std::invalid_argument);
}

TEST_CASE_FIXTURE(TrustchainFixture, "Alice can revoke a device")
{
  auto alice = trustchain.makeUser(Test::UserType::New);
  auto aliceDevice = alice.makeDevice();
  auto const aliceSession = TC_AWAIT(aliceDevice.open());

  auto const deviceId = aliceSession->deviceId().get();

  tc::promise<void> prom;
  aliceSession->connectDeviceRevoked([&] { prom.set_value({}); });

  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->revokeDevice(deviceId)));

  CHECK(TC_AWAIT(waitFor(prom)));

  REQUIRE(aliceSession->status() == Status::Stopped);
  auto core = aliceDevice.createCore(Test::SessionType::Cached);

  CHECK_EQ(TC_AWAIT(core->start(aliceDevice.identity())),
           Status::IdentityVerificationNeeded);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Alice can revoke a device while it is disconnected")
{
  auto alice = trustchain.makeUser(Test::UserType::New);
  auto aliceDevice = alice.makeDevice();
  auto const aliceSession = TC_AWAIT(aliceDevice.open());

  auto const deviceId = TC_AWAIT(aliceSession->deviceId());

  auto aliceDevice2 = alice.makeDevice();
  auto const aliceSession2 = TC_AWAIT(aliceDevice2.open());

  TC_AWAIT(aliceSession->stop());

  REQUIRE_NOTHROW(TC_AWAIT(aliceSession2->revokeDevice(deviceId)));

  tc::promise<void> prom;
  aliceSession->connectDeviceRevoked([&] { prom.set_value({}); });

  CHECK_THROWS_AS(TC_AWAIT(aliceSession->start(aliceDevice.identity())),
                  Error::OperationCanceled);

  CHECK(TC_AWAIT(waitFor(prom)));
}

// FIXME: Bad tests Bad! You either test one path or the other, but do not leave
// it to a race condition!
TEST_CASE_FIXTURE(TrustchainFixture, "Alice can revokes a device and opens it")
{
  auto alice = trustchain.makeUser(Test::UserType::New);
  auto aliceDevice = alice.makeDevice();

  {
    auto const aliceSession = TC_AWAIT(aliceDevice.open());
    auto const deviceId = TC_AWAIT(aliceSession->deviceId());
    REQUIRE_NOTHROW(TC_AWAIT(aliceSession->revokeDevice(deviceId)));
    TC_AWAIT(aliceSession->stop());
  }

  try
  {
    auto const aliceSession = aliceDevice.createCore(Test::SessionType::New);
    auto const status = TC_AWAIT(aliceSession->start(aliceDevice.identity()));
    // the revocation was handled before the session was closed
    CHECK(status == Status::IdentityVerificationNeeded);
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
  auto otherSession = TC_AWAIT(aliceSecondDevice.open());

  auto const deviceId = otherSession->deviceId().get();

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData(
      AsyncCore::encryptedSize(clearData.size()));
  TC_AWAIT(otherSession->encrypt(encryptedData.data(), clearData));

  std::vector<uint8_t> decryptedData;
  decryptedData.resize(clearData.size());

  tc::promise<void> prom;
  otherSession->connectDeviceRevoked([&] { prom.set_value({}); });

  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->revokeDevice(deviceId)));

  CHECK(TC_AWAIT(waitFor(prom)));

  REQUIRE(otherSession->status() == Status::Stopped);

  TC_AWAIT(aliceSecondDevice.open());
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
  auto const otherSession = TC_AWAIT(aliceSecondDevice.open());
  auto const otherDeviceId = otherSession->deviceId().get();

  tc::promise<void> prom;
  otherSession->connectDeviceRevoked([&] { prom.set_value({}); });

  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->revokeDevice(otherDeviceId)));

  CHECK(TC_AWAIT(waitFor(prom)));

  REQUIRE(otherSession->status() == Status::Stopped);

  {
    auto core = aliceSecondDevice.createCore(Test::SessionType::Cached);

    CHECK_EQ(TC_AWAIT(core->start(aliceSecondDevice.identity())),
             Status::IdentityVerificationNeeded);
  }

  tc::promise<void> prom2;
  aliceSession->connectDeviceRevoked([&] { prom2.set_value({}); });

  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->revokeDevice(deviceId)));

  CHECK(TC_AWAIT(waitFor(prom2)));

  REQUIRE(aliceSession->status() == Status::Stopped);

  auto core = aliceDevice.createCore(Test::SessionType::Cached);

  CHECK_EQ(TC_AWAIT(core->start(aliceDevice.identity())),
           Status::IdentityVerificationNeeded);
}
