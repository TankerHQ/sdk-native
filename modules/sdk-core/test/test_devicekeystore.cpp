#include <doctest.h>

#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/DeviceKeyStore.hpp>
#include <Tanker/Types/DeviceId.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/UniquePath.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <fmt/format.h>

using namespace Tanker;

#ifndef EMSCRIPTEN
#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Table.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DbModels/DeviceKeyStore.hpp>

namespace
{
struct OldDeviceKeyStore
{
  std::string b64PrivSigK;
  std::string b64PubSigK;
  std::string b64PrivEncK;
  std::string b64PubEncK;
  std::string b64DeviceId;
};

OldDeviceKeyStore setupDeviceKeyStoreMigration(DataStore::Connection& db)
{
  using VersionsTable = Tanker::DbModels::versions::versions;

  auto const deviceKeys = DeviceKeys::create();

  auto const b64PrivSigK =
      cppcodec::base64_rfc4648::encode(deviceKeys.signatureKeyPair.privateKey);
  auto const b64PubSigK =
      cppcodec::base64_rfc4648::encode(deviceKeys.signatureKeyPair.publicKey);
  auto const b64PrivEncK =
      cppcodec::base64_rfc4648::encode(deviceKeys.encryptionKeyPair.privateKey);
  auto const b64PubEncK =
      cppcodec::base64_rfc4648::encode(deviceKeys.encryptionKeyPair.publicKey);
  auto const b64DeviceId =
      cppcodec::base64_rfc4648::encode(deviceKeys.deviceId);

  db.execute(R"(
    CREATE TABLE device_key_store (
      id INTEGER PRIMARY KEY,
      private_signature_key TEXT NOT NULL,
      public_signature_key TEXT NOT NULL,
      private_encryption_key TEXT NOT NULL,
      public_encryption_key TEXT NOT NULL,
      device_id TEXT
    );
  )");

  db.execute(fmt::format(
      "INSERT INTO device_key_store VALUES (1, '{}', '{}', '{}', '{}', '{}')",
      b64PrivSigK,
      b64PubSigK,
      b64PrivEncK,
      b64PubEncK,
      b64DeviceId));

  db.execute(fmt::format("INSERT INTO {} VALUES ('device_key_store', 1)",
                         DataStore::tableName<VersionsTable>()));

  return {b64PrivSigK, b64PubSigK, b64PrivEncK, b64PubEncK, b64DeviceId};
}
}
#endif

TEST_CASE("device keystore")
{
  auto const dbPtr = AWAIT(DataStore::createDatabase(":memory:"));

  SUBCASE("it should open a new key store")
  {
    auto const store = AWAIT(DeviceKeyStore::open(dbPtr.get()));
    CHECK(!store->signatureKeyPair().publicKey.is_null());
    CHECK(!store->signatureKeyPair().privateKey.is_null());
    CHECK(!store->encryptionKeyPair().publicKey.is_null());
    CHECK(!store->encryptionKeyPair().privateKey.is_null());
    CHECK(store->deviceId().is_null());
  }

  SUBCASE("it should reopen a keystore")
  {
    Crypto::SignatureKeyPair previousSignatureKeyPair;
    Crypto::EncryptionKeyPair previousEncryptionKeyPair;
    auto const deviceId = make<DeviceId>("bob's device");

    {
      auto const store = AWAIT(DeviceKeyStore::open(dbPtr.get()));
      previousSignatureKeyPair = store->signatureKeyPair();
      previousEncryptionKeyPair = store->encryptionKeyPair();
      AWAIT_VOID(store->setDeviceId(deviceId));
    }

    {
      auto const store = AWAIT(DeviceKeyStore::open(dbPtr.get()));
      CHECK(previousSignatureKeyPair == store->signatureKeyPair());
      CHECK(previousEncryptionKeyPair == store->encryptionKeyPair());
      CHECK(deviceId == store->deviceId());
    }
  }

  SUBCASE("re set the deviceId with a different value")
  {
    auto const store = AWAIT(DeviceKeyStore::open(dbPtr.get()));
    REQUIRE_NOTHROW(
        AWAIT_VOID(store->setDeviceId(make<DeviceId>("bob's device"))));
    REQUIRE_THROWS(
        AWAIT_VOID(store->setDeviceId(make<DeviceId>("new device id"))));
  }
}

#ifndef EMSCRIPTEN
TEST_CASE("device keystore migration")
{
  auto const dbPtr = DataStore::createConnection(":memory:");
  auto& db = *dbPtr;

  DataStore::detail::createOrMigrateTableVersions(db);

  SUBCASE("Migration from version 1 should convert from base64")
  {
    using DeviceKeyStoreTable =
        Tanker::DbModels::device_key_store::device_key_store;
    DeviceKeyStoreTable tab{};

    auto const oldKeystore = setupDeviceKeyStoreMigration(db);

    DataStore::createOrMigrateTable<DeviceKeyStoreTable>(db);

    auto const keys = db(select(all_of(tab)).from(tab).unconditionally());
    auto const& deviceKeyStore = keys.front();

    auto const privSigK = DataStore::extractBlob<Crypto::PrivateSignatureKey>(
        deviceKeyStore.private_signature_key);
    auto const pubSigK = DataStore::extractBlob<Crypto::PublicSignatureKey>(
        deviceKeyStore.public_signature_key);
    auto const privEncK = DataStore::extractBlob<Crypto::PrivateEncryptionKey>(
        deviceKeyStore.private_encryption_key);
    auto const pubEncK = DataStore::extractBlob<Crypto::PublicEncryptionKey>(
        deviceKeyStore.public_encryption_key);
    auto const deviceId =
        DataStore::extractBlob<DeviceId>(deviceKeyStore.device_id);

    CHECK_EQ(privSigK,
             cppcodec::base64_rfc4648::decode<Crypto::PrivateSignatureKey>(
                 oldKeystore.b64PrivSigK));
    CHECK_EQ(pubSigK,
             cppcodec::base64_rfc4648::decode<Crypto::PublicSignatureKey>(
                 oldKeystore.b64PubSigK));
    CHECK_EQ(privEncK,
             cppcodec::base64_rfc4648::decode<Crypto::PrivateEncryptionKey>(
                 oldKeystore.b64PrivEncK));
    CHECK_EQ(pubEncK,
             cppcodec::base64_rfc4648::decode<Crypto::PublicEncryptionKey>(
                 oldKeystore.b64PubEncK));
    CHECK_EQ(
        deviceId,
        cppcodec::base64_rfc4648::decode<DeviceId>(oldKeystore.b64DeviceId));
  }
}
#endif
