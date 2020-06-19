#include <doctest/doctest.h>

#include <sqlpp11/ppgen.h>
#include <sqlpp11/sqlpp11.h>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Errors/Errc.hpp>
#include <Tanker/DataStore/Table.hpp>
#include <Tanker/DbModels/TrustchainInfo.hpp>
#include <Tanker/Log/Log.hpp>

#include <Helpers/Errors.hpp>
#include <Helpers/UniquePath.hpp>

TLOG_CATEGORY(DataStoreTest);

using namespace Tanker::DataStore;

namespace
{
// clang-format off
SQLPP_DECLARE_TABLE(
    (dummy)
    ,
    (id, int, SQLPP_PRIMARY_KEY)
    (value, int)
)

// clang-format on
namespace dummy
{
void createTable(Connection& db, dummy const& = {})
{
  db.execute(R"(
    CREATE TABLE IF NOT EXISTS dummy (
      id INTEGER PRIMARY KEY,
      value INTEGER
    ))");
}

void migrateTable(Connection& db, int dbVersion, dummy const& tab = {})
{
  REQUIRE_EQ(dbVersion, 1);

  db(update(tab).set(tab.value = tab.value * 2).unconditionally());
}
}

void setupDummyMigration(Connection& db)
{
  using VersionTable = Tanker::DbModels::version::version;
  VersionTable tab{};

  dummy::dummy dummy;

  dummy::createTable(db);
  db(insert_into(dummy).set(dummy.id = 1, dummy.value = 42));

  Tanker::DbModels::version::createTable(db);
  db(insert_into(tab).set(tab.db_version = 1));
}
}

TEST_CASE("Connection" * doctest::test_suite("DataStore"))
{
  Tanker::UniquePath testtmp("testtmp");
  auto const dbfile = fmt::format("{}/datastore.db", testtmp.path);

  SUBCASE("I can create a connection")
  {
    REQUIRE_NOTHROW(createConnection(dbfile));
  }

  SUBCASE("I cannot have two connections on the same exclusive database")
  {
    auto dbPtr = createConnection(dbfile);
    TANKER_CHECK_THROWS_WITH_CODE(createConnection(dbfile),
                                  Errc::DatabaseError);
  }

  SUBCASE("I can have multiple connections on a non-exclusive database")
  {
    auto dbPtr = createConnection(dbfile, {}, false);
    REQUIRE_NOTHROW(createConnection(dbfile, {}, false));
  }
}

TEST_CASE("Connection encrypted" * doctest::test_suite("DataStore") *
          doctest::skip(!hasCipher()))
{
  Tanker::UniquePath testtmp("testtmp");
  auto const dbfile = fmt::format("{}/datastore.db", testtmp.path);

  SUBCASE("Can migrate from a clear database to an encrypted database")
  {
    {
      auto dbPtr =
          std::make_unique<Connection>(sqlpp::sqlite3::connection_config{
              dbfile,
              SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
              "",
              false,
              ""});
      dbPtr->execute("CREATE TABLE lol (id INTEGER PRIMARY KEY);");
    }
    Tanker::Crypto::SymmetricKey key;
    Tanker::Crypto::randomFill(key);
    {
      auto dbPtr = createConnection(dbfile, key, true);
    }
    REQUIRE_NOTHROW(createConnection(dbfile, key, true));
  }

  SUBCASE("Can open and reconnect to an encrypted database")
  {
    Tanker::Crypto::SymmetricKey key;
    Tanker::Crypto::randomFill(key);
    {
      auto dbPtr = createConnection(dbfile, key, true);
    }
    REQUIRE_NOTHROW(createConnection(dbfile, key, true));
  }

  SUBCASE("Fails to connect with an incorrect password")
  {
    Tanker::Crypto::SymmetricKey key;
    Tanker::Crypto::randomFill(key);
    {
      auto dbPtr = createConnection(dbfile, key, true);
    }
    Tanker::Crypto::randomFill(key);
    TANKER_CHECK_THROWS_WITH_CODE(createConnection(dbfile, key, true),
                                  Errc::DatabaseError);
  }
}

TEST_CASE("Table" * doctest::test_suite("DataStore"))
{
  Tanker::UniquePath testtmp("testtmp");

  auto const dbfile = fmt::format("{}/datastore.db", testtmp.path);
  using TrustchainInfoTable =
      Tanker::DbModels::trustchain_info::trustchain_info;

  auto dbPtr = createConnection(dbfile);
  auto& db = *dbPtr;

  REQUIRE_FALSE(tableExists<TrustchainInfoTable>(db));

  SUBCASE("Creating a table")
  {
    createTable<TrustchainInfoTable>(db);
    CHECK(tableExists<TrustchainInfoTable>(db));
  }
}

TEST_CASE("Migration" * doctest::test_suite("DataStore"))
{
  Tanker::UniquePath testtmp("testtmp");
  auto const dbfile = fmt::format("{}/datastore.db", testtmp.path);

  dummy::dummy tab{};
  auto dbPtr = createConnection(dbfile);
  auto& db = *dbPtr;

  setupDummyMigration(db);

  SUBCASE("Migrate an existing table")
  {
    REQUIRE_NOTHROW(migrateTable<dummy::dummy>(db, 1));

    auto const value = static_cast<int>(
        db(select(tab.value).from(tab).unconditionally()).front().value);
    CHECK_EQ(value, 84);
  }
}
