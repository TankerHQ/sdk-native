#include <Tanker/Users/LocalUserStore.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DataStore/Sqlite/Backend.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>

#include <catch2/catch_test_macros.hpp>

using namespace Tanker;

TEST_CASE("LocalUserStore")
{
  auto db = DataStore::SqliteBackend().open(DataStore::MemoryPath, DataStore::MemoryPath);

  Users::LocalUserStore localUserStore({}, db.get());

  auto const trustchainPublicKey = make<Crypto::PublicSignatureKey>("trustchain key");
  auto const deviceId = make<Trustchain::DeviceId>("device id");
  auto const deviceKeys = DeviceKeys::create();
  auto const userKey1 = Crypto::EncryptionKeyPair{make<Crypto::PublicEncryptionKey>("pub user key 1"),
                                                  make<Crypto::PrivateEncryptionKey>("priv user key 1")};
  auto const userKey2 = Crypto::EncryptionKeyPair{make<Crypto::PublicEncryptionKey>("pub user key 2"),
                                                  make<Crypto::PrivateEncryptionKey>("priv user key 2")};

  SECTION("it should be empty at first")
  {
    CHECK(AWAIT(localUserStore.findDeviceKeys()) == std::nullopt);
  }

  SECTION("it should store and fetch data")
  {
    CHECK_NOTHROW(AWAIT_VOID(localUserStore.initializeDevice(trustchainPublicKey, deviceId, deviceKeys, {userKey1})));
    CHECK(AWAIT(localUserStore.findTrustchainPublicSignatureKey()).value() == trustchainPublicKey);
    CHECK(AWAIT(localUserStore.getDeviceId()) == deviceId);
    CHECK(AWAIT(localUserStore.getDeviceKeys()) == deviceKeys);
    CHECK(AWAIT(localUserStore.findLocalUser({})).value().userKeys() == std::vector{userKey1});
  }

  SECTION("it should add user keys and fetch them")
  {
    CHECK_NOTHROW(AWAIT_VOID(localUserStore.initializeDevice(trustchainPublicKey, deviceId, deviceKeys, {userKey1})));
    CHECK_NOTHROW(AWAIT_VOID(localUserStore.putUserKeys({userKey2})));
    // and it should ignore duplicates
    CHECK_NOTHROW(AWAIT_VOID(localUserStore.putUserKeys({userKey2})));
    CHECK(AWAIT(localUserStore.findLocalUser({})).value().userKeys() == std::vector{userKey1, userKey2});
  }
}
