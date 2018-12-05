#include <Tanker/ContactDeviceStore.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DataStore/Database.hpp>
#include <Tanker/DataStore/Table.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DbModels/ContactDevices.hpp>
#include <Tanker/Types/DeviceId.hpp>

#include <Helpers/Buffers.hpp>

#include "TrustchainBuilder.hpp"

#include <doctest.h>

using namespace Tanker;

TEST_CASE("ContactDeviceStore")
{
  auto const dbPtr = TC_AWAIT(DataStore::createDatabase(":memory:"));

  ContactDeviceStore contactDevices(dbPtr.get());
  TrustchainBuilder simulator;
  auto const alice = simulator.makeUser3("alice");
  auto const aliceDevice = alice.testEntry.asTankerUser().devices.front();

  SUBCASE("it should not find a non-existent device")
  {
    auto const unexistentDeviceId = make<DeviceId>("unexistent");

    CHECK_EQ(TC_AWAIT(contactDevices.getOptDevice(unexistentDeviceId)),
             nonstd::nullopt);
  }

  SUBCASE("it should find a device that was inserted")
  {
    TC_AWAIT(contactDevices.putDevice(alice.user.userId, aliceDevice));
    CHECK_EQ(TC_AWAIT(contactDevices.getOptDevice(aliceDevice.id)),
             aliceDevice);
  }

  SUBCASE("it should discard when inserting a duplicate device id")
  {
    TC_AWAIT(contactDevices.putDevice(alice.user.userId, aliceDevice));
    auto aliceDeviceBis = aliceDevice;
    ++aliceDeviceBis.createdAtBlkIndex;
    TC_AWAIT(contactDevices.putDevice(alice.user.userId, aliceDeviceBis));
    CHECK_EQ(TC_AWAIT(contactDevices.getOptDevice(aliceDeviceBis.id)),
             aliceDevice);
  }

  SUBCASE("it should find every device of a given user")
  {
    std::vector<Device> devices{aliceDevice};
    for (auto i = 0; i < 3; ++i)
      devices.push_back(simulator.makeDevice3("alice").testEntry.asTankerDevice());

    for (auto const& device : devices)
      TC_AWAIT(contactDevices.putDevice(alice.user.userId, device));

    auto const foundDevices = TC_AWAIT(contactDevices.getDevicesOf(alice.user.userId));
    CHECK_UNARY_FALSE(foundDevices.empty());

    CHECK_EQ(foundDevices, devices);
  }

  SUBCASE("it should return no devices when a given user does not exist")
  {
    auto const devices = TC_AWAIT(contactDevices.getDevicesOf(make<UserId>("unexistent")));

    CHECK(devices.empty());
  }
}
