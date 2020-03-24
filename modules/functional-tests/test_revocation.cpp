
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

#include <doctest.h>

#include "CheckDecrypt.hpp"

using namespace Tanker;
using namespace Tanker::Errors;
using Tanker::Functional::TrustchainFixture;

TEST_SUITE_BEGIN("Revocation");

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
        return device.id() ==
               base64DecodeArgument<Trustchain::DeviceId>(secondDeviceId);
      });
  REQUIRE(secondDeviceInList != devices.end());
  CHECK(secondDeviceInList->isRevoked());

  TC_AWAIT(aliceSecondDevice.open());
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

  std::vector<uint8_t> decryptedData;
  decryptedData.resize(clearData.size());

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

  std::vector<uint8_t> decryptedData;
  decryptedData.resize(clearData.size());

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

TEST_CASE_FIXTURE(TrustchainFixture,
                  "it chan share with a group after a revoke")
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
  auto const aliceEmail = Email{"alice1@mail.com"};
  auto const aliceProvisionalIdentity = Identity::createProvisionalIdentity(
      cppcodec::base64_rfc4648::encode(trustchain.id), aliceEmail);
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
  auto const aliceEmail = Email{"alice1@mail.com"};
  auto const aliceProvisionalIdentity = Identity::createProvisionalIdentity(
      cppcodec::base64_rfc4648::encode(trustchain.id), aliceEmail);
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
