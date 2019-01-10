#include <Tanker/UserKeyStore.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/base64.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Error.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/UniquePath.hpp>

#include <doctest.h>

using namespace Tanker;

#ifndef EMSCRIPTEN
#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Table.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DbModels/UserKeys.hpp>
#include <Tanker/DbModels/Versions.hpp>

namespace
{
struct OldUserKeys
{
  std::string b64PrivateEncryptionKey;
  std::string b64PublicEncryptionKey;
};

OldUserKeys setupUserKeysMigration(DataStore::Connection& db)
{
  using VersionsTable = Tanker::DbModels::versions::versions;

  auto const keyPair = Crypto::makeEncryptionKeyPair();

  auto const b64PublicKey = base64::encode(keyPair.publicKey);
  auto const b64PrivateKey = base64::encode(keyPair.privateKey);

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
  db.execute(fmt::format("INSERT INTO {} VALUES ('user_keys', 1)",
                         DataStore::tableName<VersionsTable>()));

  return {b64PrivateKey, b64PublicKey};
}
}
#endif

TEST_CASE("user keys")
{
  auto const dbPtr = AWAIT(DataStore::createDatabase(":memory:"));

  SUBCASE("it should create and destroy a UserKeyStore")
  {
    UserKeyStore keys(dbPtr.get());
  }

  SUBCASE("it should not find a non-existent key")
  {
    auto const unexistentPubKey =
        make<Crypto::PublicEncryptionKey>("unexistent");

    UserKeyStore keys(dbPtr.get());
    CHECK_THROWS_AS(AWAIT(keys.getKeyPair(unexistentPubKey)),
                    Error::UserKeyNotFound);
  }

  SUBCASE("it should discard a second user key with the same public key")
  {
    auto const pubKey = make<Crypto::PublicEncryptionKey>("pub key...");
    auto const privKey = make<Crypto::PrivateEncryptionKey>("private key~~");
    auto const privKey2 = make<Crypto::PrivateEncryptionKey>("private key2~~");

    UserKeyStore keys(dbPtr.get());

    AWAIT_VOID(keys.putPrivateKey(pubKey, privKey));
    AWAIT_VOID(keys.putPrivateKey(pubKey, privKey2));

    CHECK(AWAIT(keys.getKeyPair(pubKey)).privateKey == privKey);
  }

  SUBCASE("it should find a key that was inserted")
  {
    auto const pubKey = make<Crypto::PublicEncryptionKey>("pub key...");
    auto const privKey = make<Crypto::PrivateEncryptionKey>("private key~~");

    UserKeyStore keys(dbPtr.get());

    AWAIT_VOID(keys.putPrivateKey(pubKey, privKey));
    auto const gotKeyPair = AWAIT(keys.getKeyPair(pubKey));

    CHECK(privKey == gotKeyPair.privateKey);
  }

  SUBCASE("getLastKeyPair should throw if there are no key")
  {
    UserKeyStore keys(dbPtr.get());
    CHECK_THROWS_AS(AWAIT(keys.getLastKeyPair()), Error::UserKeyNotFound);
  }

  SUBCASE("getLastKeyPair should get the last inserted key")
  {
    auto const privKey = make<Crypto::PrivateEncryptionKey>("private key~~");

    auto const lastKeyPair = Crypto::EncryptionKeyPair{
        make<Crypto::PublicEncryptionKey>("last pub key..."),
        make<Crypto::PrivateEncryptionKey>("last private key~~")};

    UserKeyStore keys(dbPtr.get());

    AWAIT_VOID(keys.putPrivateKey(
        make<Crypto::PublicEncryptionKey>("pub key1..."), privKey));
    AWAIT_VOID(keys.putPrivateKey(
        make<Crypto::PublicEncryptionKey>("pub key2..."), privKey));
    AWAIT_VOID(keys.putPrivateKey(
        make<Crypto::PublicEncryptionKey>("pub key3..."), privKey));
    AWAIT_VOID(
        keys.putPrivateKey(lastKeyPair.publicKey, lastKeyPair.privateKey));
    auto const gotLastKeyPair = AWAIT(keys.getLastKeyPair());

    CHECK(gotLastKeyPair == lastKeyPair);
  }
}

#ifndef EMSCRIPTEN
TEST_CASE("user keys migration")
{
  using UserKeysTable = Tanker::DbModels::user_keys::user_keys;

  auto const dbPtr = DataStore::createConnection(":memory:");
  auto& db = *dbPtr;
  DataStore::detail::createOrMigrateTableVersions(db);

  SUBCASE("Migration from version 1 should convert from base64")
  {
    auto const oldKeys = setupUserKeysMigration(db);

    UserKeysTable tab;

    DataStore::createOrMigrateTable<UserKeysTable>(db);
    auto const keys = db(select(all_of(tab)).from(tab).unconditionally());
    auto const& userKeys = keys.front();

    auto const privK = DataStore::extractBlob<Crypto::PrivateEncryptionKey>(
        userKeys.private_encryption_key);
    auto const pubK = DataStore::extractBlob<Crypto::PublicEncryptionKey>(
        userKeys.public_encryption_key);

    CHECK_EQ(privK,
             base64::decode<Crypto::PrivateEncryptionKey>(
                 oldKeys.b64PrivateEncryptionKey));
    CHECK_EQ(pubK,
             base64::decode<Crypto::PublicEncryptionKey>(
                 oldKeys.b64PublicEncryptionKey));
  }
}
#endif
