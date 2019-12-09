
#include <Tanker/Users/LocalUser.hpp>

#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include <doctest.h>

using namespace Tanker;
using Tanker::Users::LocalUser;
using namespace Tanker::Errors;

#ifndef EMSCRIPTEN
#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Table.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DbModels/DeviceKeyStore.hpp>
#include <Tanker/DbModels/UserKeys.hpp>

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
      cppcodec::base64_rfc4648::encode(Trustchain::DeviceId{});

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

  return {b64PrivSigK, b64PubSigK, b64PrivEncK, b64PubEncK, b64DeviceId};
}
struct OldUserKeys
{
  std::string b64PrivateEncryptionKey;
  std::string b64PublicEncryptionKey;
};

OldUserKeys setupUserKeysMigration(DataStore::Connection& db)
{
  auto const keyPair = Crypto::makeEncryptionKeyPair();

  auto const b64PublicKey = cppcodec::base64_rfc4648::encode(keyPair.publicKey);
  auto const b64PrivateKey =
      cppcodec::base64_rfc4648::encode(keyPair.privateKey);

  db.execute(R"(
    CREATE TABLE user_keys (
      id INTEGER PRIMARY KEY,
      public_encryption_key TEXT NOT NULL UNIQUE,
      private_encryption_key TEXT NOT NULL
    );
  )");

  db.execute(fmt::format("INSERT INTO user_keys VALUES(1, '{}', '{}')",
                         b64PublicKey,
                         b64PrivateKey));

  return {b64PrivateKey, b64PublicKey};
}
}

TEST_CASE("LocalUser migration")
{
  auto const dbPtr = DataStore::createConnection(":memory:");
  auto& db = *dbPtr;

  SUBCASE("Migration from version 1 should convert from base64")
  {
    using DeviceKeyStoreTable =
        Tanker::DbModels::device_key_store::device_key_store;
    DeviceKeyStoreTable tab{};

    auto const oldKeystore = setupDeviceKeyStoreMigration(db);

    DataStore::createTable<DeviceKeyStoreTable>(db);
    DataStore::migrateTable<DeviceKeyStoreTable>(db, 1);

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
        DataStore::extractBlob<Trustchain::DeviceId>(deviceKeyStore.device_id);

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
    CHECK_EQ(deviceId,
             cppcodec::base64_rfc4648::decode<Trustchain::DeviceId>(
                 oldKeystore.b64DeviceId));
  }
  SUBCASE("Migration from version 1 should convert from base64")
  {
    auto const oldKeys = setupUserKeysMigration(db);
    using UserKeysTable = Tanker::DbModels::user_keys::user_keys;

    UserKeysTable tab{};

    DataStore::createTable<UserKeysTable>(db);
    DataStore::migrateTable<UserKeysTable>(db, 1);
    auto const keys = db(select(all_of(tab)).from(tab).unconditionally());
    auto const& userKeys = keys.front();

    auto const privK = DataStore::extractBlob<Crypto::PrivateEncryptionKey>(
        userKeys.private_encryption_key);
    auto const pubK = DataStore::extractBlob<Crypto::PublicEncryptionKey>(
        userKeys.public_encryption_key);

    CHECK_EQ(privK,
             cppcodec::base64_rfc4648::decode<Crypto::PrivateEncryptionKey>(
                 oldKeys.b64PrivateEncryptionKey));
    CHECK_EQ(pubK,
             cppcodec::base64_rfc4648::decode<Crypto::PublicEncryptionKey>(
                 oldKeys.b64PublicEncryptionKey));
  }
}
#endif

TEST_CASE("LocalUser")
{
  auto const identity = Identity::createIdentity(Trustchain::TrustchainId{},
                                                 Crypto::PrivateSignatureKey{},
                                                 Trustchain::UserId{});
  auto const dbPtr = AWAIT(DataStore::createDatabase(":memory:"));
  auto const store = AWAIT(LocalUser::open(identity, dbPtr.get()));

  SUBCASE("it should open a new key store")
  {
    CHECK(!store->deviceKeys().signatureKeyPair.publicKey.is_null());
    CHECK(!store->deviceKeys().signatureKeyPair.privateKey.is_null());
    CHECK(!store->deviceKeys().encryptionKeyPair.publicKey.is_null());
    CHECK(!store->deviceKeys().encryptionKeyPair.privateKey.is_null());
    CHECK(store->deviceId().is_null());
  }

  SUBCASE("it should reopen a keystore")
  {
    DeviceKeys deviceKeys;
    auto const deviceId = make<Trustchain::DeviceId>("bob's device");

    {
      deviceKeys = store->deviceKeys();
      AWAIT_VOID(store->setDeviceId(deviceId));
    }

    {
      auto const store2 = AWAIT(LocalUser::open(identity, dbPtr.get()));
      CHECK(deviceKeys == store2->deviceKeys());
      CHECK(deviceId == store2->deviceId());
    }
  }

  SUBCASE("it should not find a non-existent key")
  {
    auto const unexistentPubKey =
        make<Crypto::PublicEncryptionKey>("unexistent");

    auto const key = AWAIT(store->findKeyPair(unexistentPubKey));
    CHECK_EQ(key, std::nullopt);
  }

  SUBCASE("it should discard a second user key with the same public key")
  {
    auto const keyPair1 = Crypto::makeEncryptionKeyPair();
    auto const keyPair2 = Crypto::EncryptionKeyPair{
        keyPair1.publicKey,
        make<Crypto::PrivateEncryptionKey>("private key2~~")};

    AWAIT_VOID(store->insertUserKey(keyPair1));
    AWAIT_VOID(store->insertUserKey(keyPair2));

    CHECK_EQ(AWAIT(store->findKeyPair(keyPair1.publicKey)).value(), keyPair1);
  }

  SUBCASE("it should find a key that was inserted")
  {
    auto const keyPair1 = Crypto::makeEncryptionKeyPair();
    auto const keyPair2 = Crypto::makeEncryptionKeyPair();

    AWAIT_VOID(store->insertUserKey(keyPair1));
    AWAIT_VOID(store->insertUserKey(keyPair2));
    auto const gotKeyPair = AWAIT(store->findKeyPair(keyPair1.publicKey));

    CHECK_NOTHROW(gotKeyPair.value());
    CHECK_EQ(keyPair1, gotKeyPair.value());
  }

  SUBCASE("currentKeyPair should throw if there are no key")
  {
    TANKER_CHECK_THROWS_WITH_CODE(AWAIT(store->currentKeyPair()),
                                  Errc::InternalError);
  }

  SUBCASE("currentKeyPair should get the last inserted key")
  {
    auto const secretKey = make<Crypto::PrivateEncryptionKey>("secret key~~");
    auto const keyPair1 = Crypto::EncryptionKeyPair{
        make<Crypto::PublicEncryptionKey>("pub key1..."), secretKey};
    auto const keyPair2 = Crypto::EncryptionKeyPair{
        make<Crypto::PublicEncryptionKey>("pub key2..."), secretKey};
    auto const keyPair3 = Crypto::EncryptionKeyPair{
        make<Crypto::PublicEncryptionKey>("pub key3..."), secretKey};
    auto const lastUserKey = Crypto::makeEncryptionKeyPair();

    AWAIT_VOID(store->insertUserKey(keyPair1));
    AWAIT_VOID(store->insertUserKey(keyPair2));
    AWAIT_VOID(store->insertUserKey(keyPair3));
    AWAIT_VOID(store->insertUserKey(lastUserKey));
    auto const gotLastKeyPair = AWAIT(store->currentKeyPair());

    CHECK_EQ(gotLastKeyPair, lastUserKey);
  }
}
