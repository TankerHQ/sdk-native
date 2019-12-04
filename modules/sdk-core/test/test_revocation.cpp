#include <Tanker/Revocation.hpp>

#include <Tanker/ContactStore.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/DeviceKeyStore.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Groups/Accessor.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Errors.hpp>

#include "TestVerifier.hpp"
#include "TrustchainBuilder.hpp"

#include <doctest.h>

#include <Helpers/Buffers.hpp>

using namespace Tanker;
using namespace Tanker::Errors;

TEST_CASE("Revocation tests")
{
  TrustchainBuilder builder;
  auto const rootEntry = builder.entries().front();

  auto const db = AWAIT(DataStore::createDatabase(":memory:"));
  auto const userResult = builder.makeUser("bob");
  auto const deviceResult = builder.makeDevice("bob");
  auto const aliceResult = builder.makeUser1("alice");

  auto const contactStore =
      builder.makeContactStoreWith({"bob", "alice"}, db.get());

  SUBCASE("EnsureDeviceIsFromUser throws if given a bad deviceId")
  {
    TANKER_CHECK_THROWS_WITH_CODE(AWAIT_VOID(Revocation::ensureDeviceIsFromUser(
                                      aliceResult.user.devices[0].id,
                                      userResult.user.userId,
                                      *contactStore.get())),
                                  Errc::InvalidArgument);
  }

  SUBCASE(
      "EnsureDeviceIsFromUser does not throws if deviceId belongs to userId")
  {
    CHECK_NOTHROW(AWAIT_VOID(Revocation::ensureDeviceIsFromUser(
        deviceResult.device.id, userResult.user.userId, *contactStore.get())));
  }

  SUBCASE("getUserFromUserId throws if userId is invalid")
  {
    auto userId = userResult.user.userId;
    userId[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(
        AWAIT(Revocation::getUserFromUserId(userId, *contactStore.get())),
        Errc::InternalError);
  }

  SUBCASE("getUserFromUserId throws if userId belongs to a user V1")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        AWAIT(Revocation::getUserFromUserId(aliceResult.user.userId,
                                            *contactStore.get())),
        Errc::InternalError);
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
    auto const encryptedPrivateKeys = AWAIT(
        Revocation::encryptPrivateKeyForDevices(deviceResult.user,
                                                userResult.user.devices[0].id,
                                                encryptionKeyPair.privateKey));

    REQUIRE(encryptedPrivateKeys.size() == 1);

    auto const deviceKeyStore =
        AWAIT(DeviceKeyStore::open(db.get(), deviceResult.device.keys));

    auto const decryptedPrivateKey = Revocation::decryptPrivateKeyForDevice(
        deviceKeyStore, encryptedPrivateKeys[0].second);

    CHECK(decryptedPrivateKey == encryptionKeyPair.privateKey);
  }
}
