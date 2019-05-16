#include <Tanker/DbModels/ResourceIdToKeyPublish.hpp>

#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Table.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DataStore/Version.hpp>
#include <Tanker/Log.hpp>

#include <cassert>
#include <exception>

TLOG_CATEGORY(resource_id_to_key_publish);

namespace Tanker
{
namespace DbModels
{
namespace resource_id_to_key_publish
{
void createTable(DataStore::Connection& db, resource_id_to_key_publish const&)
{
  db.execute(R"(
    CREATE TABLE IF NOT EXISTS resource_id_to_key_publish (
      resource_id BLOB NOT NULL PRIMARY KEY,
      hash BLOB NOT NULL
    );
  )");
}

void migrateTable(DataStore::Connection& db,
                  int currentVersion,
                  resource_id_to_key_publish const& tab)
{
  assert(currentVersion < DataStore::latestVersion());

  TINFO("Migrating from version {} to {}",
        currentVersion,
        DataStore::latestVersion());
  switch (currentVersion)
  {
  case 0:
  case 1:
    break;
  default:
    assert(false && "Unreachable code");
    std::terminate();
  }
}
}
}
}
