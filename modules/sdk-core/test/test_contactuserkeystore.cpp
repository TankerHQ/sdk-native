#include <Tanker/ContactUserKeyStore.hpp>

#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Database.hpp>
#include <Tanker/DataStore/Table.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DbModels/ContactUserKeys.hpp>
#include <Tanker/DbModels/Versions.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Types/UserId.hpp>

#include <tconcurrent/coroutine.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/UniquePath.hpp>

#include <doctest.h>

using namespace Tanker;

namespace
{
struct OldContactUserKeys
{
  std::string b64UserId;
  std::string b64PublicEncryptionKey;
};

OldContactUserKeys setupContactUserKeysMigration(DataStore::Connection& db)
{
  using VersionsTable = Tanker::DbModels::versions::versions;

  auto const keyPair = Crypto::makeEncryptionKeyPair();

  auto const b64PublicKey = base64::encode(keyPair.publicKey);
  auto const b64UserId = base64::encode(make<UserId>("michel"));

  db.execute(R"(
    CREATE TABLE contact_user_keys (
      id INTEGER PRIMARY KEY,
      user_id TEXT NOT NULL UNIQUE,
      public_encryption_key TEXT NOT NULL
    );
  )");

  db.execute(fmt::format("INSERT INTO contact_user_keys VALUES (1, '{}', '{}')",
                         b64UserId,
                         b64PublicKey));

  db.execute(fmt::format("INSERT INTO {} VALUES ('contact_user_keys', 1)",
                         DataStore::tableName<VersionsTable>()));

  return {b64UserId, b64PublicKey};
}
}

TEST_CASE("contact user keys")
{
  auto const dbPtr = AWAIT(DataStore::createDatabase(":memory:"));

  SUBCASE("it should create and destroy a ContactUserKeyStore")
  {
    ContactUserKeyStore keys(dbPtr.get());
  }

  SUBCASE("it should not find a non-existent key")
  {
    auto const unexistentUserId = make<UserId>("unexistent");

    ContactUserKeyStore keys(dbPtr.get());
    CHECK(AWAIT(keys.getUserKey(unexistentUserId)) == nonstd::nullopt);
  }

  SUBCASE("it should find a key that was inserted")
  {
    auto const userId = make<UserId>("userId");
    auto const pubKey = make<Crypto::PublicEncryptionKey>("pub key...");

    ContactUserKeyStore keys(dbPtr.get());

    AWAIT_VOID(keys.putUserKey(userId, pubKey));
    CHECK(AWAIT(keys.getUserKey(userId)) == pubKey);
  }

  SUBCASE("it should override an old key with a new one")
  {
    auto const userId = make<UserId>("userId");
    auto const pubKey1 = make<Crypto::PublicEncryptionKey>("pub key...");
    auto const pubKey2 = make<Crypto::PublicEncryptionKey>("pub key2...");

    ContactUserKeyStore keys(dbPtr.get());

    AWAIT_VOID(keys.putUserKey(userId, pubKey1));
    AWAIT_VOID(keys.putUserKey(userId, pubKey2));
    CHECK(AWAIT(keys.getUserKey(userId)) == pubKey2);
  }
}

TEST_CASE("contact user keys migration")
{
  using ContactUserKeysTable = DbModels::contact_user_keys::contact_user_keys;

  auto const dbPtr = DataStore::createConnection(":memory:");
  auto& db = *dbPtr;

  DataStore::detail::createOrMigrateTableVersions(db);

  SUBCASE("Migration from version 1 should convert from base64")
  {
    ContactUserKeysTable tab;

    auto const oldKeys = setupContactUserKeysMigration(db);

    DataStore::createOrMigrateTable<ContactUserKeysTable>(db);
    auto const keys = db(select(all_of(tab)).from(tab).unconditionally());
    auto const& contactUserKeys = keys.front();

    auto const userId = DataStore::extractBlob<UserId>(contactUserKeys.user_id);
    auto const pubK = DataStore::extractBlob<Crypto::PublicEncryptionKey>(
        contactUserKeys.public_encryption_key);

    CHECK_EQ(userId, base64::decode<UserId>(oldKeys.b64UserId));
    CHECK_EQ(pubK,
             base64::decode<Crypto::PublicEncryptionKey>(
                 oldKeys.b64PublicEncryptionKey));
  }

  SUBCASE("Migration from version 2 should allow null public encryption keys")
  {
    ContactUserKeysTable tab;

    CHECK_NOTHROW(
        db(insert_into(tab).set(tab.user_id = make<UserId>("unexistent").base(),
                                tab.public_encryption_key = sqlpp::null)));
  }
}
