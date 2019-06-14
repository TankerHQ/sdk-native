#include <Tanker/ContactStore.hpp>

#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include "TrustchainBuilder.hpp"

#include <doctest.h>
#include <optional.hpp>
#include <tconcurrent/coroutine.hpp>

using namespace Tanker;

TEST_CASE("ContactStore")
{
  auto const dbPtr = AWAIT(DataStore::createDatabase(":memory:"));

  ContactStore contacts(dbPtr.get());
  TrustchainBuilder builder;
  auto const alice = builder.makeUser3("alice").user.asTankerUser();
  auto const aliceDevice = alice.devices.front();

  SUBCASE("it should not find a non-existent user")
  {
    auto const unexistentUserId = make<Trustchain::UserId>("unexistent");

    CHECK_EQ(AWAIT(contacts.findUser(unexistentUserId)), nonstd::nullopt);
  }

  SUBCASE("it should throw when adding a user twice")
  {
    AWAIT_VOID(contacts.putUser(alice));
    TANKER_CHECK_THROWS_WITH_CODE(AWAIT_VOID(contacts.putUser(alice)),
                                  Errors::Errc::InternalError);
  }

  SUBCASE("it should find a user that was inserted")
  {
    AWAIT_VOID(contacts.putUser(alice));
    CHECK_EQ(AWAIT(contacts.findUser(alice.id)), alice);
  }

  SUBCASE("it should find a user v1 that was inserted")
  {
    auto const v1User = builder.makeUser1("v1").user.asTankerUser();
    CHECK_UNARY_FALSE(!!v1User.userKey);
    AWAIT_VOID(contacts.putUser(v1User));
    CHECK_EQ(AWAIT(contacts.findUser(v1User.id)), v1User);
  }

  SUBCASE("it should update a user's userKey")
  {
    AWAIT_VOID(contacts.putUser(alice));
    auto aliceBis = alice;
    aliceBis.userKey = make<Crypto::PublicEncryptionKey>("pubkey");
    AWAIT_VOID(contacts.putUserKey(alice.id, *aliceBis.userKey));
    CHECK_EQ(AWAIT(contacts.findUser(alice.id)), aliceBis);
  }

  SUBCASE("it should add a new user device")
  {
    AWAIT_VOID(contacts.putUser(alice));
    auto aliceBis = alice;
    auto const newDevice = builder.makeDevice3("alice").device.asTankerDevice();
    aliceBis.devices.push_back(newDevice);
    AWAIT_VOID(contacts.putUserDevice(alice.id, newDevice));
    CHECK_EQ(AWAIT(contacts.findUser(alice.id)), aliceBis);
  }

  SUBCASE("it should discard an existing user device id")
  {
    AWAIT_VOID(contacts.putUser(alice));
    auto aliceDeviceBis = aliceDevice;
    ++aliceDeviceBis.createdAtBlkIndex;
    AWAIT_VOID(contacts.putUserDevice(alice.id, aliceDeviceBis));

    CHECK_EQ(AWAIT(contacts.findDevice(aliceDevice.id)), aliceDevice);
  }

  SUBCASE("it should not find a non-existent device")
  {
    auto const unexistentDeviceId = make<Trustchain::DeviceId>("unexistent");

    CHECK_EQ(AWAIT(contacts.findDevice(unexistentDeviceId)), nonstd::nullopt);
  }

  SUBCASE("it should find a device that was inserted")
  {
    AWAIT_VOID(contacts.putUser(alice));
    CHECK_EQ(AWAIT(contacts.findDevice(aliceDevice.id)), aliceDevice);
  }

  SUBCASE("it should find every device of a given user")
  {
    auto aliceBis = alice;
    for (auto i = 0; i < 3; ++i)
    {
      aliceBis.devices.push_back(
          builder.makeDevice3("alice").device.asTankerDevice());
    }

    AWAIT_VOID(contacts.putUser(aliceBis));

    auto const foundDevices = AWAIT(contacts.findUserDevices(alice.id));
    CHECK_UNARY_FALSE(foundDevices.empty());

    CHECK_EQ(foundDevices, aliceBis.devices);
  }

  SUBCASE("it should return no devices when a given user does not exist")
  {
    auto const devices =
        AWAIT(contacts.findUserDevices(make<Trustchain::UserId>("unexistent")));

    CHECK_UNARY(devices.empty());
  }

  SUBCASE("it should throw when inserting a device with an invalid user id")
  {
    CHECK_THROWS_AS(AWAIT_VOID(contacts.putUserDevice(
                        make<Trustchain::UserId>("unexistent"), aliceDevice)),
                    std::runtime_error);
  }

  SUBCASE("it should not find a a userId with a superseded userPublicKey")
  {
    AWAIT_VOID(contacts.putUser(alice));
    AWAIT_VOID(contacts.putUserKey(
        alice.id, make<Crypto::PublicEncryptionKey>("pubkey")));
    CHECK_EQ(AWAIT(contacts.findUserIdByUserPublicKey(*alice.userKey)),
             nonstd::nullopt);
  }

  SUBCASE("it should find a userId with a valid userPublicKey")
  {
    AWAIT_VOID(contacts.putUser(alice));
    CHECK_EQ(AWAIT(contacts.findUserIdByUserPublicKey(*alice.userKey)),
             alice.id);
  }

  SUBCASE("it should find a userId with a deviceId")
  {
    AWAIT_VOID(contacts.putUser(alice));
    CHECK_EQ(AWAIT(contacts.findUserIdByDeviceId(aliceDevice.id)), alice.id);
  }

  SUBCASE("it should revoke a device")
  {
    AWAIT_VOID(contacts.putUser(alice));
    AWAIT_VOID(
        contacts.revokeDevice(aliceDevice.id, aliceDevice.createdAtBlkIndex));
    auto const device = AWAIT(contacts.findDevice(aliceDevice.id));
    CHECK_EQ(device.value().revokedAtBlkIndex.value(),
             aliceDevice.createdAtBlkIndex);
  }

  SUBCASE("it should not find userId with old userPublicEncyptionKey")
  {
    AWAIT_VOID(contacts.putUser(alice));
    AWAIT_VOID(contacts.rotateContactPublicEncryptionKey(
        alice.id, make<Crypto::PublicEncryptionKey>("pubkey")));
    CHECK_EQ(AWAIT(contacts.findUserIdByUserPublicKey(*alice.userKey)),
             nonstd::nullopt);
  }

  SUBCASE("it should find a userId with an updated userPublicKey")
  {
    AWAIT_VOID(contacts.putUser(alice));
    auto const newKey = make<Crypto::PublicEncryptionKey>("pubkey");
    AWAIT_VOID(contacts.rotateContactPublicEncryptionKey(alice.id, newKey));
    CHECK_EQ(AWAIT(contacts.findUserIdByUserPublicKey(newKey)), alice.id);
  }
}
