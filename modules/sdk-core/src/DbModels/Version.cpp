#include <Tanker/DbModels/Version.hpp>

#include <Tanker/DataStore/Connection.hpp>

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
