#include <Tanker/ResourceKeyStore.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/ResourceKeyNotFound.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>

#include <doctest.h>
#include <cppcodec/base64_rfc4648.hpp>

using namespace Tanker;

#ifndef EMSCRIPTEN
#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Table.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DbModels/ResourceKeys.hpp>

namespace
{
struct OldResourceKeys
{
  std::string b64Mac;
  std::string b64ResourceKey;
};

OldResourceKeys setupResourceKeysMigration(DataStore::Connection& db)
{
  auto const resourceKey = Crypto::makeSymmetricKey();

  auto const b64Mac =
      cppcodec::base64_rfc4648::encode(make<Trustchain::ResourceId>("michel"));
  auto const b64ResourceKey = cppcodec::base64_rfc4648::encode(resourceKey);

  db.execute(R"(
    CREATE TABLE resource_keys (
      id INTEGER PRIMARY KEY,
      mac TEXT NOT NULL,
      resource_key TEXT NOT NULL
    );
  )");

  db.execute(fmt::format("INSERT INTO resource_keys VALUES (1, '{}', '{}')",
                         b64Mac,
                         b64ResourceKey));

  return {b64Mac, b64ResourceKey};
}
}
#endif

TEST_CASE("resource keys")
{
  auto const dbPtr = AWAIT(DataStore::createDatabase(":memory:"));

  SUBCASE("it should create and destroy a ResourceKeyStore")
  {
    ResourceKeyStore keys(dbPtr.get());
  }

  SUBCASE("it should not find a non-existent key")
  {
    auto const unexistentMac = make<Trustchain::ResourceId>("unexistent");

    ResourceKeyStore keys(dbPtr.get());
    CHECK_THROWS_AS(AWAIT(keys.getKey(unexistentMac)),
                    Error::ResourceKeyNotFound);
  }

  SUBCASE("it should find a key that was inserted")
  {
    auto const resourceId = make<Trustchain::ResourceId>("mymac");
    auto const key = make<Crypto::SymmetricKey>("mykey");

    ResourceKeyStore keys(dbPtr.get());

    AWAIT_VOID(keys.putKey(resourceId, key));
    auto const key2 = AWAIT(keys.getKey(resourceId));

    CHECK(key == key2);
  }

  SUBCASE("it should ignore a duplicate key and keep the first")
  {
    auto const resourceId = make<Trustchain::ResourceId>("mymac");
    auto const key = make<Crypto::SymmetricKey>("mykey");
    auto const key2 = make<Crypto::SymmetricKey>("mykey2");

    ResourceKeyStore keys(dbPtr.get());

    AWAIT_VOID(keys.putKey(resourceId, key));
    AWAIT_VOID(keys.putKey(resourceId, key2));
    auto const gotKey = AWAIT(keys.getKey(resourceId));

    CHECK_EQ(key, gotKey);
  }
}

#ifndef EMSCRIPTEN
TEST_CASE("Migration")
{
  auto const dbPtr = DataStore::createConnection(":memory:");
  auto& db = *dbPtr;

  SUBCASE("Migration from version 1 should convert from base64")
  {
    using ResourceKeysTable = Tanker::DbModels::resource_keys::resource_keys;
    ResourceKeysTable tab{};

    auto const oldKeys = setupResourceKeysMigration(db);

    DataStore::createTable<ResourceKeysTable>(db);
    DataStore::migrateTable<ResourceKeysTable>(db, 1);
    auto const keys = db(select(all_of(tab)).from(tab).unconditionally());
    auto const& resourceKeys = keys.front();

    auto const resourceId =
        DataStore::extractBlob<Trustchain::ResourceId>(resourceKeys.mac);
    auto const key =
        DataStore::extractBlob<Crypto::SymmetricKey>(resourceKeys.resource_key);

    CHECK_EQ(resourceId,
             cppcodec::base64_rfc4648::decode<Trustchain::ResourceId>(oldKeys.b64Mac));
    CHECK_EQ(key,
             cppcodec::base64_rfc4648::decode<Crypto::SymmetricKey>(
                 oldKeys.b64ResourceKey));
  }
}
#endif
