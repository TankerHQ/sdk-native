#include <Tanker/Revocation.hpp>

#include <Tanker/ContactStore.hpp>
#include <Tanker/Crypto/KeyFormat.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/DeviceKeyStore.hpp>
#include <Tanker/Groups/GroupAccessor.hpp>
#include <Tanker/RecipientNotFound.hpp>
#include <Tanker/Types/DeviceId.hpp>

#include <Helpers/Await.hpp>

#include "TestVerifier.hpp"
#include "TrustchainBuilder.hpp"

#include <doctest.h>

#include <Helpers/Buffers.hpp>

using namespace Tanker;

TEST_CASE("Revocation namespace")
{
  TrustchainBuilder builder;
  auto const rootEntry = blockToUnverifiedEntry(builder.blocks().front());

  auto const db = AWAIT(DataStore::createDatabase(":memory:"));
  auto const userResult = builder.makeUser("bob");
  auto const deviceResult = builder.makeDevice("bob");
  auto const aliceResult = builder.makeUser1("alice");

  auto const contactStore =
      builder.makeContactStoreWith({"bob", "alice"}, db.get());

  SUBCASE("EnsureDeviceIsFromUser throws if given a bad deviceId")
  {
    CHECK_THROWS_AS(AWAIT_VOID(Revocation::ensureDeviceIsFromUser(
                        aliceResult.user.devices[0].keys.deviceId,
                        userResult.user.userId,
                        *contactStore.get())),
                    Error::DeviceNotFound);
  }

  SUBCASE(
      "EnsureDeviceIsFromUser does not throws if deviceId belongs to userId")
  {
    CHECK_NOTHROW(AWAIT_VOID(
        Revocation::ensureDeviceIsFromUser(deviceResult.device.keys.deviceId,
                                           userResult.user.userId,
                                           *contactStore.get())));
  }

  SUBCASE("getUserFromUserId throws if userId is invalid")
  {
    auto userId = userResult.user.userId;
    userId[0]++;
    CHECK_THROWS_AS(
        AWAIT(Revocation::getUserFromUserId(userId, *contactStore.get())),
        Error::InternalError);
  }

  SUBCASE("getUserFromUserId throws if userId belongs to a user V1")
  {
    CHECK_THROWS_AS(AWAIT(Revocation::getUserFromUserId(aliceResult.user.userId,
                                                        *contactStore.get())),
                    Error::InternalError);
  }

  SUBCASE("getUserFromUserId correctly finds bob user")
  {
    auto const user = AWAIT(Revocation::getUserFromUserId(
        userResult.user.userId, *contactStore.get()));
    CHECK(user.userKey == userResult.user.asTankerUser().userKey);
  }

  SUBCASE("devicePrivateKey can be encrypted & decrypted")
  {
    auto const encryptionKeyPair = Crypto::makeEncryptionKeyPair();
    auto const encryptedPrivateKeys =
        AWAIT(Revocation::encryptPrivateKeyForDevices(
            deviceResult.user,
            userResult.user.devices[0].keys.deviceId,
            encryptionKeyPair.privateKey));

    REQUIRE(encryptedPrivateKeys.size() == 1);

    auto const deviceKeyStore =
        AWAIT(DeviceKeyStore::open(db.get(), deviceResult.device.keys));

    auto const decryptedPrivateKey = Revocation::decryptPrivateKeyForDevice(
        deviceKeyStore, encryptedPrivateKeys[0].privateEncryptionKey);

    CHECK(decryptedPrivateKey == encryptionKeyPair.privateKey);
  }
}
