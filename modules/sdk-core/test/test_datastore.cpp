#include <catch2/catch_test_macros.hpp>

#include <sqlpp11/ppgen.h>
#include <sqlpp11/sqlpp11.h>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Errors/Errc.hpp>
#include <Tanker/Log/Log.hpp>

#include <Helpers/Errors.hpp>
#include <Helpers/UniquePath.hpp>

TLOG_CATEGORY(DataStoreTest);

using namespace Tanker::DataStore;

TEST_CASE("Connection")
{
  Tanker::UniquePath testtmp("testtmp");
  auto const dbfile = fmt::format("{}/datastore.db", testtmp.path);

  SECTION("I can create a connection")
  {
    REQUIRE_NOTHROW(createConnection(dbfile));
  }

  SECTION("I cannot have two connections on the same exclusive database")
  {
    auto dbPtr = createConnection(dbfile);
    TANKER_CHECK_THROWS_WITH_CODE(createConnection(dbfile),
                                  Errc::DatabaseLocked);
  }

  SECTION("I can have multiple connections on a non-exclusive database")
  {
    auto dbPtr = createConnection(dbfile, {}, false);
    REQUIRE_NOTHROW(createConnection(dbfile, {}, false));
  }
}
