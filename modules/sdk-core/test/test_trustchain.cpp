#include <doctest.h>

#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/TrustchainStore.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/UnverifiedEntry.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/UniquePath.hpp>

#include <cppcodec/base64_rfc4648.hpp>

#include "TestVerifier.hpp"
#include "TrustchainBuilder.hpp"

using Tanker::Trustchain::Actions::Nature;

using namespace Tanker;

#ifndef EMSCRIPTEN
#include <Tanker/DataStore/Table.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DbModels/Trustchain.hpp>
#include <Tanker/DbModels/TrustchainIndexes.hpp>
#include <Tanker/DbModels/Versions.hpp>

#include <sqlpp11/sqlpp11.h>

namespace
{
struct OldBlock
{
  std::string b64Hash;
  std::string b64Author;
  std::string b64Action;
};

struct OldIndex
{
  std::string b64Hash;
  std::string b64Value;
};

OldBlock setupTrustchainMigration(DataStore::Connection& db)
{
  using VersionsTable = DbModels::versions::versions;

  auto const b64Hash =
      cppcodec::base64_rfc4648::encode(make<Crypto::Hash>("hash"));
  auto const b64Author =
      cppcodec::base64_rfc4648::encode(make<Crypto::Hash>("author"));
  auto const b64Record = cppcodec::base64_rfc4648::encode("record");

  db.execute(R"(
    CREATE TABLE trustchain (
      idx INTEGER PRIMARY KEY,
      nature INTEGER NOT NULL,
      author TEXT NOT NULL,
      record TEXT NOT NULL,
      hash TEXT NOT NULL UNIQUE
    );
  )");

  db.execute(
      fmt::format("INSERT INTO trustchain VALUES(1, 1, '{}', '{}', '{}')",
                  b64Author,
                  b64Record,
                  b64Hash));
  db.execute(fmt::format("INSERT INTO {} VALUES ('trustchain', 1)",
                         DataStore::tableName<VersionsTable>()));

  return {b64Hash, b64Author, b64Record};
}

OldIndex setupTrustchainIndexesMigration(DataStore::Connection& db)
{
  using VersionsTable = DbModels::versions::versions;

  auto const b64Hash =
      cppcodec::base64_rfc4648::encode(make<Crypto::Hash>("hash"));
  auto const b64Value = cppcodec::base64_rfc4648::encode("value");

  db.execute(R"(
    CREATE TABLE trustchain_indexes (
      id_index INTEGER PRIMARY KEY,
      hash TEXT NOT NULL,
      type INTEGER NOT NULL,
      value TEXT NOT NULL,
      UNIQUE(type, value, hash)
    );
  )");

  db.execute(
      fmt::format("INSERT INTO trustchain_indexes VALUES(1, '{}', 1, '{}')",
                  b64Hash,
                  b64Value));
  db.execute(fmt::format("INSERT INTO {} VALUES ('trustchain_indexes', 1)",
                         DataStore::tableName<VersionsTable>()));

  return {b64Hash, b64Value};
}
}
#endif

TEST_CASE("trustchain")
{
  auto const dbPtr = AWAIT(DataStore::createDatabase(":memory:"));

  SUBCASE("it should open a new trustchain store")
  {
    TrustchainStore trustchain(dbPtr.get());
  }

  SUBCASE("it should add entries to the trustchain and update last index")
  {
    TrustchainStore trustchain(dbPtr.get());
    AWAIT_VOID(trustchain.addEntry(Entry{10,
                                         Nature::TrustchainCreation,
                                         Crypto::Hash{},
                                         Action{TrustchainCreation{}},
                                         Crypto::Hash{}}));

    CHECK(10 == AWAIT(trustchain.getLastIndex()));
  }

  SUBCASE("it should close and reopen a trustchain")
  {
    {
      TrustchainStore trustchain(dbPtr.get());
      AWAIT_VOID(trustchain.addEntry(Entry{10,
                                           Nature::TrustchainCreation,
                                           Crypto::Hash{},
                                           Action{TrustchainCreation{}},
                                           Crypto::Hash{}}));
    }
    {
      TrustchainStore trustchain(dbPtr.get());
      CHECK(10 == AWAIT(trustchain.getLastIndex()));
    }
  }

  SUBCASE("it should find a key publish to user by resource id")
  {
    TrustchainBuilder builder;
    auto const alice = builder.makeUser("alice");
    auto const bob = builder.makeUser("bob");

    auto const resourceId = make<Crypto::Mac>("the mac");
    auto const key = make<Crypto::SymmetricKey>("the key");
    auto const share =
        builder.shareToUser(alice.user.devices[0], bob.user, resourceId, key);

    TrustchainStore trustchain(dbPtr.get());
    for (auto const& block : builder.blocks())
      AWAIT_VOID(
          trustchain.addEntry(toVerifiedEntry(blockToUnverifiedEntry(block))));

    auto const entry = AWAIT(trustchain.findKeyPublish(resourceId));

    CHECK(entry.value() == toVerifiedEntry(blockToUnverifiedEntry(share)));
  }

  SUBCASE("it should find a key publish to user group by resource id")
  {
    TrustchainBuilder builder;
    auto const alice = builder.makeUser("alice");
    auto const group = builder.makeGroup(alice.user.devices[0], {alice.user});

    auto const resourceId = make<Crypto::Mac>("the mac");
    auto const key = make<Crypto::SymmetricKey>("the key");
    auto const share = builder.shareToUserGroup(
        alice.user.devices[0], group.group, resourceId, key);

    TrustchainStore trustchain(dbPtr.get());
    for (auto const& block : builder.blocks())
      AWAIT_VOID(
          trustchain.addEntry(toVerifiedEntry(blockToUnverifiedEntry(block))));

    auto const entry = AWAIT(trustchain.findKeyPublish(resourceId));

    CHECK(entry.value() == toVerifiedEntry(blockToUnverifiedEntry(share)));
  }

  SUBCASE("it should not throw when inserting the same block twice")
  {
    TrustchainBuilder builder;
    auto const alice = builder.makeUser("alice");
    auto const bob = builder.makeUser("bob");

    auto const resourceId = make<Crypto::Mac>("the mac");
    auto const key = make<Crypto::SymmetricKey>("the key");
    auto const share =
        builder.shareToUser(alice.user.devices[0], bob.user, resourceId, key);

    TrustchainStore trustchain(dbPtr.get());
    for (auto const& block : builder.blocks())
      AWAIT_VOID(
          trustchain.addEntry(toVerifiedEntry(blockToUnverifiedEntry(block))));

    CHECK_NOTHROW(AWAIT_VOID(trustchain.addEntry(
        toVerifiedEntry(blockToUnverifiedEntry(builder.blocks().back())))));
  }

  SUBCASE("it should not throw when sharing the same resource twice")
  {
    TrustchainBuilder builder;
    auto const alice = builder.makeUser("alice");
    auto const bob = builder.makeUser("bob");

    auto const resourceId = make<Crypto::Mac>("the mac");
    auto const key = make<Crypto::SymmetricKey>("the key");
    auto const share =
        builder.shareToUser(alice.user.devices[0], bob.user, resourceId, key);
    auto const share2 =
        builder.shareToUser(alice.user.devices[0], bob.user, resourceId, key);

    TrustchainStore trustchain(dbPtr.get());
    for (auto const& block : builder.blocks())
      CHECK_NOTHROW(AWAIT_VOID(
          trustchain.addEntry(toVerifiedEntry(blockToUnverifiedEntry(block)))));
  }
}

#ifndef EMSCRIPTEN
TEST_CASE("trustchain migration")
{
  auto const dbPtr = DataStore::createConnection(":memory:");
  auto& db = *dbPtr;

  DataStore::detail::createOrMigrateTableVersions(db);

  SUBCASE("Migration from version 1 should convert from base64")
  {
    using DataStore::extractBlob;

    SUBCASE("Trustchain")
    {
      using TrustchainTable = DbModels::trustchain::trustchain;

      auto const oldRootBlock = setupTrustchainMigration(db);

      DataStore::createOrMigrateTable<TrustchainTable>(db);

      TrustchainTable tab{};

      auto const blocks = db(select(all_of(tab)).from(tab).unconditionally());
      auto const& rootBlock = blocks.front();

      auto const hash = extractBlob<Crypto::Hash>(rootBlock.hash);
      auto const author = extractBlob<Crypto::Hash>(rootBlock.author);
      auto const action = extractBlob<std::vector<uint8_t>>(rootBlock.action);

      CHECK_EQ(
          hash,
          cppcodec::base64_rfc4648::decode<Crypto::Hash>(oldRootBlock.b64Hash));
      CHECK_EQ(author,
               cppcodec::base64_rfc4648::decode<Crypto::Hash>(
                   oldRootBlock.b64Author));
      CHECK_EQ(action,
               cppcodec::base64_rfc4648::decode(oldRootBlock.b64Action));
    }

    SUBCASE("TrustchainIndexes")
    {
      using TrustchainIndexesTable =
          DbModels::trustchain_indexes::trustchain_indexes;

      auto const oldIndex = setupTrustchainIndexesMigration(db);

      DataStore::createOrMigrateTable<TrustchainIndexesTable>(db);

      TrustchainIndexesTable tab{};

      auto const indexes = db(select(all_of(tab)).from(tab).unconditionally());
      auto const& index = indexes.front();

      auto const hash = extractBlob<Crypto::Hash>(index.hash);
      // TODO add constructor with iterators in Crypto/Types.hpp
      auto const sp = extractBlob(index.value);
      std::vector<uint8_t> const value(sp.begin(), sp.end());

      CHECK_EQ(value, cppcodec::base64_rfc4648::decode(oldIndex.b64Value));
      CHECK_EQ(
          hash,
          cppcodec::base64_rfc4648::decode<Crypto::Hash>(oldIndex.b64Hash));
    }
  }
}
#endif
