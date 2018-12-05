#include <doctest.h>

#include <optional.hpp>

#include <sqlpp11/ppgen.h>
#include <sqlpp11/sqlpp11.h>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Table.hpp>
#include <Tanker/DbModels/Trustchain.hpp>
#include <Tanker/DbModels/Versions.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/ssl.hpp>

#include <Helpers/UniquePath.hpp>

#include <boost/filesystem.hpp>

TLOG_CATEGORY(DataStoreTest);

namespace bfs = boost::filesystem;
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
constexpr int currentTableVersion(dummy const& = {})
{
  return 2;
}

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
  using VersionsTable = Tanker::DbModels::versions::versions;
  VersionsTable tab;

  dummy::dummy dummy;

  dummy::createTable(db);
  db(insert_into(dummy).set(dummy.id = 1, dummy.value = 42));

  Tanker::DataStore::detail::createOrMigrateTableVersions(db);
  db(insert_into(tab).set(tab.name = "dummy", tab.version = 1));
}
}

TEST_CASE("Connection" * doctest::test_suite("DataStore"))
{
  Tanker::UniquePath testtmp("testtmp");
  auto const dbfile =
      fmt::format("{}", (testtmp.path / "datastore.db").string());
  SUBCASE("I can create a connection")
  {
    REQUIRE_NOTHROW(createConnection(dbfile));
  }

  SUBCASE("I cannot have two connections on the same exclusive database")
  {
    auto dbPtr = createConnection(dbfile);
    REQUIRE_THROWS(createConnection(dbfile));
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
  auto const dbfile =
      fmt::format("{}", (testtmp.path / "datastore.db").string());

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
    CHECK_THROWS_AS(createConnection(dbfile, key, true),
                    Tanker::Error::InternalError);
  }
}

TEST_CASE("Table" * doctest::test_suite("DataStore"))
{
  using VersionsTable = Tanker::DbModels::versions::versions;
  Tanker::UniquePath testtmp("testtmp");

  auto const dbfile =
      fmt::format("{}", (testtmp.path / "datastore.db").string());
  using TrustchainTable = Tanker::DbModels::trustchain::trustchain;

  auto dbPtr = createConnection(dbfile);
  auto& db = *dbPtr;

  REQUIRE_FALSE(tableExists<VersionsTable>(db));
  REQUIRE_FALSE(tableExists<TrustchainTable>(db));

  SUBCASE("Creating a table")
  {
    createOrMigrateTable<TrustchainTable>(db);
    CHECK(tableExists<TrustchainTable>(db));
  }

  SUBCASE("Creating a table will also create the versions table")
  {
    createOrMigrateTable<TrustchainTable>(db);
    REQUIRE(tableExists<TrustchainTable>(db));
    CHECK(tableExists<VersionsTable>(db));
  }

  SUBCASE("Creating any table will update its version")
  {
    createOrMigrateTable<TrustchainTable>(db);
    REQUIRE(tableExists<TrustchainTable>(db));

    auto const optVersion = tableVersion<TrustchainTable>(db);
    REQUIRE(optVersion != nonstd::nullopt);

    auto const currentVersion = currentTableVersion(TrustchainTable{});
    CHECK_EQ(*optVersion, currentVersion);
  }

  SUBCASE("Creating any table will also update the versions table's version")
  {
    createOrMigrateTable<TrustchainTable>(db);
    CHECK(tableExists<TrustchainTable>(db));
    CHECK(tableExists<VersionsTable>(db));

    auto const optVersion = tableVersion<VersionsTable>(db);
    REQUIRE(optVersion != nonstd::nullopt);

    auto const currentVersion = currentTableVersion(VersionsTable{});
    CHECK_EQ(*optVersion, currentVersion);
  }
}

TEST_CASE("Migration" * doctest::test_suite("DataStore"))
{
  Tanker::UniquePath testtmp("testtmp");
  auto const dbfile =
      fmt::format("{}", (testtmp.path / "datastore.db").string());

  dummy::dummy tab;
  auto dbPtr = createConnection(dbfile);
  auto& db = *dbPtr;

  setupDummyMigration(db);

  SUBCASE("Trying to create an existing table will result in its migration")
  {
    REQUIRE_NOTHROW(createOrMigrateTable<dummy::dummy>(db));

    auto const value = static_cast<int>(
        db(select(tab.value).from(tab).unconditionally()).front().value);
    CHECK_EQ(value, 84);
  }

  SUBCASE("Throw when a database version is too high")
  {
    using VersionsTable = Tanker::DbModels::versions::versions;

    VersionsTable tab;
    db(update(tab)
           .set(tab.version = dummy::currentTableVersion() + 1)
           .where(tab.name == tableName<dummy::dummy>()));

    CHECK_THROWS_AS(createOrMigrateTable<dummy::dummy>(db),
                    Tanker::Error::MigrationFailed);
  }
}
