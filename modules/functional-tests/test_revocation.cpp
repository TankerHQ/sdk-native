
#include <Tanker/AsyncCore.hpp>
#include <Tanker/Errors/Errc.hpp>
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

TEST_SUITE_BEGIN("revocation");

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
  CHECK(secondDeviceInList->revokedAtBlkIndex().has_value());

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
  CHECK(secondSession->status() == Status::Stopped);

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

TEST_SUITE_END();
