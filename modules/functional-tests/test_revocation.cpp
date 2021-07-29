
#include <Tanker/AsyncCore.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Utils.hpp>

#include <Tanker/Functional/TrustchainFixture.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>
#include <Helpers/WaitFor.hpp>

#include <doctest/doctest.h>

#include "CheckDecrypt.hpp"

using namespace Tanker;
using namespace Tanker::Errors;
using Tanker::Functional::TrustchainFixture;

TEST_SUITE_BEGIN("Revocation");

TEST_CASE_FIXTURE(TrustchainFixture, "Alice can list her devices")
{
  auto alice = trustchain.makeUser(Functional::UserType::New);
  auto aliceDevice = alice.makeDevice();
  auto const aliceSession = TC_AWAIT(aliceDevice.open());

  auto aliceSecondDevice = alice.makeDevice();
  auto secondSession = TC_AWAIT(aliceSecondDevice.open());

  auto devices = TC_AWAIT(aliceSession->getDeviceList());
  std::vector<SDeviceId> deviceIds;
  for (auto const& device : devices)
    deviceIds.push_back(mgs::base64::encode<SDeviceId>(device.id()));
  auto expectedDeviceIds = std::vector{TC_AWAIT(aliceSession->deviceId()),
                                       TC_AWAIT(secondSession->deviceId())};
  std::sort(deviceIds.begin(), deviceIds.end());
  std::sort(expectedDeviceIds.begin(), expectedDeviceIds.end());
  CHECK(deviceIds == expectedDeviceIds);
}

TEST_CASE_FIXTURE(TrustchainFixture, "Alice can revoke a device")
{
  auto alice = trustchain.makeUser(Functional::UserType::New);
  auto aliceDevice = alice.makeDevice();
  auto const aliceSession = TC_AWAIT(aliceDevice.open());

  auto aliceSecondDevice = alice.makeDevice();
  auto secondSession = TC_AWAIT(aliceSecondDevice.open());

  auto const secondDeviceId = secondSession->deviceId().get();

  tc::promise<void> wasEmitted;
  secondSession->connectDeviceRevoked([&] { wasEmitted.set_value({}); });

  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->revokeDevice(secondDeviceId)));

  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(secondSession->encrypt(make_buffer("will fail"))),
      Errc::DeviceRevoked);
  CHECK(secondSession->status() == Status::Stopped);
  CHECK_NOTHROW(TC_AWAIT(waitFor(wasEmitted)));

  auto const devices = TC_AWAIT(aliceSession->getDeviceList());
  auto const secondDeviceInList =
      std::find_if(devices.begin(), devices.end(), [&](auto const& device) {
        return device.id() == base64DecodeArgument<Trustchain::DeviceId>(
                                  secondDeviceId, "secondDeviceId");
      });
  REQUIRE(secondDeviceInList != devices.end());
  CHECK(secondDeviceInList->isRevoked());

  TC_AWAIT(aliceSecondDevice.open());
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Triggering self destruct twice doesn't crash")
{
  auto alice = trustchain.makeUser(Functional::UserType::New);
  auto aliceDevice = alice.makeDevice();
  auto const aliceSession = TC_AWAIT(aliceDevice.open());

  auto aliceSecondDevice = alice.makeDevice();
  auto secondSession = TC_AWAIT(aliceSecondDevice.open());

  auto const secondDeviceId = secondSession->deviceId().get();

  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->revokeDevice(secondDeviceId)));

  // This is a race, one of the future will finish with DeviceRevoked, and the
  // other will be canceled and finish with tc::operation_canceled (which gets
  // translated in the C layer).
  auto fut1 = secondSession->encrypt(make_buffer("will fail"));
  auto fut2 = secondSession->encrypt(make_buffer("will fail"));

  int nbDeviceRevoked = 0;
  int nbOperationCanceled = 0;
  auto awaitAndCountExceptions = [&](auto fut) -> tc::cotask<void> {
    try
    {
      TC_AWAIT(std::move(fut));
    }
    catch (Errors::Exception const& e)
    {
      if (e.errorCode() == Errc::DeviceRevoked)
        nbDeviceRevoked++;
      else
        throw;
    }
    catch (tc::operation_canceled const&)
    {
      nbOperationCanceled++;
    }
  };
  CHECK_NOTHROW(TC_AWAIT(awaitAndCountExceptions(std::move(fut1))));
  CHECK_NOTHROW(TC_AWAIT(awaitAndCountExceptions(std::move(fut2))));
  CHECK(nbDeviceRevoked == 1);
  CHECK(nbOperationCanceled == 1);
  CHECK(secondSession->status() == Status::Stopped);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Alice can revoke a device while it is offline")
{
  auto alice = trustchain.makeUser(Functional::UserType::New);
  auto aliceDevice = alice.makeDevice();
  auto const aliceSession = TC_AWAIT(aliceDevice.open());

  auto aliceSecondDevice = alice.makeDevice();
  SDeviceId secondDeviceId;
  {
    auto secondSession =
        TC_AWAIT(aliceSecondDevice.open(Functional::SessionType::New));
    secondDeviceId = secondSession->deviceId().get();
  }

  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->revokeDevice(secondDeviceId)));

  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(aliceSecondDevice.open(Functional::SessionType::New)),
      Errc::DeviceRevoked);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Alice can recreate a device and decrypt after a revocation")
{
  auto alice = trustchain.makeUser(Functional::UserType::New);
  auto aliceDevice = alice.makeDevice();
  auto const aliceSession = TC_AWAIT(aliceDevice.open());

  auto aliceSecondDevice = alice.makeDevice();
  auto secondSession = TC_AWAIT(aliceSecondDevice.open());

  auto const secondDeviceId = secondSession->deviceId().get();

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData(
      AsyncCore::encryptedSize(clearData.size()));
  TC_AWAIT(secondSession->encrypt(encryptedData.data(), clearData));

  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->revokeDevice(secondDeviceId)));

  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(secondSession->encrypt(clearData)),
                                Errc::DeviceRevoked);

  TC_AWAIT(aliceSecondDevice.open());
  REQUIRE_UNARY(TC_AWAIT(checkDecrypt(
      {aliceSecondDevice}, {std::make_tuple(clearData, encryptedData)})));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "multiple devices can be successively revoked")
{
  auto alice = trustchain.makeUser(Functional::UserType::New);
  auto aliceDevice = alice.makeDevice();
  auto const aliceSession = TC_AWAIT(aliceDevice.open());

  auto aliceSecondDevice = alice.makeDevice();
  auto secondSession = TC_AWAIT(aliceSecondDevice.open());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData(
      AsyncCore::encryptedSize(clearData.size()));
  TC_AWAIT(secondSession->encrypt(encryptedData.data(), clearData));

  tc::promise<void> wasEmitted;
  secondSession->connectDeviceRevoked([&] { wasEmitted.set_value({}); });

  // First Revoke
  REQUIRE_NOTHROW(
      TC_AWAIT(aliceSession->revokeDevice(secondSession->deviceId().get())));

  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(secondSession->encrypt(clearData)),
                                Errc::DeviceRevoked);
  CHECK(secondSession->status() == Status::Stopped);
  CHECK_NOTHROW(TC_AWAIT(waitFor(wasEmitted)));

  secondSession = TC_AWAIT(aliceSecondDevice.open());
  REQUIRE_UNARY(TC_AWAIT(checkDecrypt(
      {aliceSecondDevice}, {std::make_tuple(clearData, encryptedData)})));

  //   Second Revoke
  wasEmitted = {};
  secondSession->connectDeviceRevoked([&] { wasEmitted.set_value({}); });
  REQUIRE_NOTHROW(
      TC_AWAIT(aliceSession->revokeDevice(secondSession->deviceId().get())));

  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(secondSession->encrypt(clearData)),
                                Errc::DeviceRevoked);
  CHECK(secondSession->status() == Status::Stopped);
  CHECK_NOTHROW(TC_AWAIT(waitFor(wasEmitted)));

  TC_AWAIT(aliceSecondDevice.open());
  REQUIRE_UNARY(TC_AWAIT(checkDecrypt(
      {aliceSecondDevice}, {std::make_tuple(clearData, encryptedData)})));
}

TEST_CASE_FIXTURE(TrustchainFixture, "it can share with a user after a revoke")
{
  auto alice = trustchain.makeUser(Functional::UserType::New);
  auto aliceDevice = alice.makeDevice();
  auto const aliceSession = TC_AWAIT(aliceDevice.open());

  auto aliceSecondDevice = alice.makeDevice();
  auto aliceSecondSession = TC_AWAIT(aliceSecondDevice.open());

  REQUIRE_NOTHROW(TC_AWAIT(
      aliceSecondSession->revokeDevice(aliceSecondSession->deviceId().get())));

  auto const clearData = make_buffer("my clear data is clear");

  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto bobSession = TC_AWAIT(bobDevice.open());
  auto encrypted =
      TC_AWAIT(bobSession->encrypt(clearData, {alice.spublicIdentity()}));
  auto result_data = TC_AWAIT(aliceSession->decrypt(encrypted));
  REQUIRE_EQ(result_data, clearData);
}

TEST_CASE_FIXTURE(TrustchainFixture, "it can share with a group after a revoke")
{
  auto alice = trustchain.makeUser(Functional::UserType::New);
  auto aliceDevice = alice.makeDevice();
  auto const aliceSession = TC_AWAIT(aliceDevice.open());

  auto aliceSecondDevice = alice.makeDevice();
  auto aliceSecondSession = TC_AWAIT(aliceSecondDevice.open());

  REQUIRE_NOTHROW(TC_AWAIT(
      aliceSecondSession->revokeDevice(aliceSecondSession->deviceId().get())));

  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto bobSession = TC_AWAIT(bobDevice.open());
  auto const groupId = TC_AWAIT(bobSession->createGroup(
      {bob.spublicIdentity(), alice.spublicIdentity()}));

  auto const clearData = make_buffer("my clear data is clear");
  auto const encrypted =
      TC_AWAIT(bobSession->encrypt(clearData, {}, {groupId}));
  auto result_data = TC_AWAIT(aliceSession->decrypt(encrypted));
  REQUIRE_EQ(result_data, clearData);
}

TEST_CASE_FIXTURE(TrustchainFixture, "it can claim a resource after a revoke")
{
  auto alice = trustchain.makeUser(Functional::UserType::New);
  auto aliceDevice = alice.makeDevice();
  auto const aliceEmail = Email{"alice1.test@tanker.io"};
  auto const aliceProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), aliceEmail);
  auto const aliceSession = TC_AWAIT(aliceDevice.open());

  auto aliceSecondDevice = alice.makeDevice();
  auto aliceSecondSession = TC_AWAIT(aliceSecondDevice.open());
  REQUIRE_NOTHROW(TC_AWAIT(
      aliceSecondSession->revokeDevice(aliceSecondSession->deviceId().get())));

  auto const clearData = make_buffer("my clear data is clear");

  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto bobSession = TC_AWAIT(bobDevice.open());

  auto const encrypted =
      TC_AWAIT(bobSession->encrypt(clearData,
                                   {SPublicIdentity{Identity::getPublicIdentity(
                                       aliceProvisionalIdentity)}}));

  REQUIRE_EQ(TC_AWAIT(aliceSession->attachProvisionalIdentity(
                          SSecretProvisionalIdentity{aliceProvisionalIdentity}))
                 .status,
             Status::IdentityVerificationNeeded);
  auto const aliceVerificationCode = TC_AWAIT(getVerificationCode(aliceEmail));
  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->verifyProvisionalIdentity(
      Unlock::EmailVerification{aliceEmail, aliceVerificationCode})));

  auto const result_data = TC_AWAIT(aliceSession->decrypt(encrypted));
  REQUIRE_EQ(result_data, clearData);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "it can claim and decrypt a resource after a revoke")
{
  auto alice = trustchain.makeUser(Functional::UserType::New);
  auto aliceDevice = alice.makeDevice();
  auto const aliceEmail = Email{"alice1.test@tanker.io"};
  auto const aliceProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), aliceEmail);
  auto const aliceSession = TC_AWAIT(aliceDevice.open());

  auto aliceSecondDevice = alice.makeDevice();
  auto aliceSecondSession = TC_AWAIT(aliceSecondDevice.open());
  REQUIRE_NOTHROW(TC_AWAIT(
      aliceSecondSession->revokeDevice(aliceSecondSession->deviceId().get())));

  auto aliceThirdDevice = alice.makeDevice();
  auto aliceThirdSession = TC_AWAIT(aliceThirdDevice.open());

  auto const clearData = make_buffer("my clear data is clear");

  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto bobSession = TC_AWAIT(bobDevice.open());

  auto const encrypted =
      TC_AWAIT(bobSession->encrypt(clearData,
                                   {SPublicIdentity{Identity::getPublicIdentity(
                                       aliceProvisionalIdentity)}}));

  REQUIRE_EQ(TC_AWAIT(aliceSession->attachProvisionalIdentity(
                          SSecretProvisionalIdentity{aliceProvisionalIdentity}))
                 .status,
             Status::IdentityVerificationNeeded);
  auto const aliceVerificationCode = TC_AWAIT(getVerificationCode(aliceEmail));
  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->verifyProvisionalIdentity(
      Unlock::EmailVerification{aliceEmail, aliceVerificationCode})));

  auto const result_data = TC_AWAIT(aliceThirdSession->decrypt(encrypted));
  REQUIRE_EQ(result_data, clearData);
}

TEST_SUITE_END();
