#include <Tanker/DbModels/KeyPublishes.hpp>

#include <cassert>

namespace Tanker
{
namespace DbModels
{
namespace key_publishes
{
void createTable(DataStore::Connection& db, key_publishes const&)
{
  db.execute(R"(
    CREATE TABLE IF NOT EXISTS key_publishes (
      resource_id BLOB PRIMARY KEY,
      nature INTEGER NOT NULL,
      recipient BLOB NOT NULL,
      key BLOB NOT NULL
    );
  )");
}

void migrateTable(DataStore::Connection& db,
                  int dbVersion,
                  key_publishes const&)
{
  assert(dbVersion < currentTableVersion());
}
}
}
}
