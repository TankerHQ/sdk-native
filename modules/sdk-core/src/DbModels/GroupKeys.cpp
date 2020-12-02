#include <Tanker/DbModels/GroupKeys.hpp>

#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Version.hpp>
#include <Tanker/Log/Log.hpp>

#include <cassert>
#include <exception>

TLOG_CATEGORY(group_keys);

namespace Tanker
{
namespace DbModels
{
namespace group_keys
{
void createTable(DataStore::Connection& db, group_keys const&)
{
  db.execute(R"(
    CREATE TABLE IF NOT EXISTS group_keys (
      public_encryption_key BLOB PRIMARY KEY,
      private_encryption_key BLOB NOT NULL UNIQUE,
      group_id BLOB NOT NULL
    );
  )");
}

void migrateTable(DataStore::Connection& db, int currentVersion, group_keys const&)
{
  if (currentVersion != 0)
  {
    assert(false && "New table can not exist in the old migration system");
    std::terminate();
  }
}
}
}
}
