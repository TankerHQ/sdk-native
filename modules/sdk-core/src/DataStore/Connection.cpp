#include <Tanker/DataStore/Connection.hpp>

#include <Tanker/DataStore/Errors/Errc.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>

#include <Tanker/Log/Log.hpp>

#include <boost/algorithm/hex.hpp>
#include <sqlite3.h>
#include <sqlpp11/ppgen.h>
#include <sqlpp11/sqlpp11.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>

TLOG_CATEGORY(DataStore);

namespace Tanker
{
namespace DataStore
{
namespace
{
// clang-format off
SQLPP_DECLARE_TABLE(
  (access)
  ,
  (last_access, int, SQLPP_NOT_NULL)
)
// clang-format on

using Table = access::access;

void makeExclusive(ConnPtr& db)
{
  // This does not actually take the lock, we need to trigger a write operation
  // on the database for it to be taken. That's why we create a table and run an
  // update on it.
  db->execute(R"(
    PRAGMA locking_mode = EXCLUSIVE;
  )");
  db->execute(R"(
    CREATE TABLE IF NOT EXISTS access (
      last_access INT NOT NULL
    );
  )");

  Table access;

  // Yes, it actually (tries to) write, and takes the lock
  (*db)(update(access).set(access.last_access = 0).unconditionally());
}
}

ConnPtr createConnection(std::string const& dbPath,
                         std::optional<Crypto::SymmetricKey> userSecret,
                         bool exclusive)
{
  TDEBUG("creating database {}", dbPath);
  try
  {
    auto db = [&] {
      SCOPE_TIMER("open", DB);
      return std::make_unique<Connection>(sqlpp::sqlite3::connection_config{
          dbPath.c_str(),
          SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
          "",
          false,
          "",
      });
    }();

    {
      SCOPE_TIMER("finalize open", DB);
      // Check the open succeeded
      db->execute("SELECT count(*) FROM sqlite_master");
      if (exclusive)
        makeExclusive(db);
    }
    return db;
  }
  catch (sqlpp::exception const& e)
  {
    std::string const msg = e.what();
    if (msg.find("database is locked") != std::string::npos)
      throw Errors::Exception(Errc::DatabaseLocked,
                              "database is locked by another Tanker instance");
    else
      throw Errors::Exception(Errc::DatabaseError, e.what());
  }
  catch (std::exception const& e)
  {
    throw Errors::formatEx(Errors::Errc::InternalError,
                           FMT_STRING("could not open database: {:s}: {:s}"),
                           dbPath,
                           e.what());
  }
}
}
}
