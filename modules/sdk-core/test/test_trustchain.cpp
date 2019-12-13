#include <doctest.h>

#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/TrustchainStore.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/UniquePath.hpp>

#include <cppcodec/base64_rfc4648.hpp>

#include "TestVerifier.hpp"
#include "TrustchainBuilder.hpp"

using Tanker::Trustchain::Action;
using Tanker::Trustchain::Actions::Nature;

using namespace Tanker;

#ifndef EMSCRIPTEN
#include <Tanker/DataStore/Table.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DbModels/Trustchain.hpp>

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

  return {b64Hash, b64Author, b64Record};
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

  SUBCASE("it should return nullopt when there is no signature key")
  {
    TrustchainStore trustchain(dbPtr.get());

    CHECK_EQ(AWAIT(trustchain.findPublicSignatureKey()), std::nullopt);
  }

  SUBCASE("it should add entries to the trustchain and update last index")
  {
    TrustchainStore trustchain(dbPtr.get());
    AWAIT_VOID(trustchain.addEntry(
        Entry{10,
              Nature::TrustchainCreation,
              Crypto::Hash{},
              Action{Trustchain::Actions::TrustchainCreation{}},
              Crypto::Hash{}}));

    CHECK(10 == AWAIT(trustchain.getLastIndex()));
  }

  SUBCASE("it should close and reopen a trustchain")
  {
    {
      TrustchainStore trustchain(dbPtr.get());
      AWAIT_VOID(trustchain.addEntry(
          Entry{10,
                Nature::TrustchainCreation,
                Crypto::Hash{},
                Action{Trustchain::Actions::TrustchainCreation{}},
                Crypto::Hash{}}));
    }
    {
      TrustchainStore trustchain(dbPtr.get());
      CHECK(10 == AWAIT(trustchain.getLastIndex()));
    }
  }

  SUBCASE("it should throw when inserting the same block twice")
  {
    TrustchainBuilder builder;
    auto const alice = builder.makeUser("alice");
    auto const bob = builder.makeUser("bob");

    auto const resourceId = make<Trustchain::ResourceId>("the resourceId");
    auto const key = make<Crypto::SymmetricKey>("the key");
    auto const share =
        builder.shareToUser(alice.user.devices[0], bob.user, resourceId, key);

    TrustchainStore trustchain(dbPtr.get());
    for (auto const& block : builder.blocks())
      AWAIT_VOID(
          trustchain.addEntry(toVerifiedEntry(blockToServerEntry(block))));

    CHECK_THROWS(AWAIT_VOID(trustchain.addEntry(
        toVerifiedEntry(blockToServerEntry(builder.blocks().back())))));
  }

  SUBCASE("it should not throw when sharing the same resource twice")
  {
    TrustchainBuilder builder;
    auto const alice = builder.makeUser("alice");
    auto const bob = builder.makeUser("bob");

    auto const resourceId = make<Trustchain::ResourceId>("the resourceId");
    auto const key = make<Crypto::SymmetricKey>("the key");
    auto const share =
        builder.shareToUser(alice.user.devices[0], bob.user, resourceId, key);
    auto const share2 =
        builder.shareToUser(alice.user.devices[0], bob.user, resourceId, key);

    TrustchainStore trustchain(dbPtr.get());
    for (auto const& block : builder.blocks())
      CHECK_NOTHROW(AWAIT_VOID(
          trustchain.addEntry(toVerifiedEntry(blockToServerEntry(block)))));
  }
}

#ifndef EMSCRIPTEN
TEST_CASE("trustchain migration")
{
  auto const dbPtr = DataStore::createConnection(":memory:");
  auto& db = *dbPtr;

  SUBCASE("Migration from version 1 should convert from base64")
  {
    using DataStore::extractBlob;

    SUBCASE("Trustchain")
    {
      using TrustchainTable = DbModels::trustchain::trustchain;

      auto const oldRootBlock = setupTrustchainMigration(db);

      DataStore::createTable<TrustchainTable>(db);
      DataStore::migrateTable<TrustchainTable>(db, 1);

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
  }
}
#endif
