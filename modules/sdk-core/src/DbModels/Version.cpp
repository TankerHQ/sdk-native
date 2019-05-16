#include <Tanker/DbModels/Version.hpp>

#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Version.hpp>

#include <sqlpp11/insert.h>
#include <sqlpp11/sqlite3/insert_or.h>

#include <cassert>

namespace Tanker
{
namespace DbModels
{
namespace version
{
void createTable(DataStore::Connection& db, version const& tab)
{
  db.execute(R"(
    CREATE TABLE version (
      db_version INTEGER PRIMARY KEY
    )
  )");
  db.execute(R"(
    INSERT INTO version VALUES (0)
  )");
}
}
}
}
