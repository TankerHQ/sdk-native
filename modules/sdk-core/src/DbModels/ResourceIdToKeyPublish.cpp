#include <Tanker/DbModels/ResourceIdToKeyPublish.hpp>

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Crypto/base64.hpp>
#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Table.hpp>
#include <Tanker/DataStore/Utils.hpp>
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
                  int dbVersion,
                  resource_id_to_key_publish const& tab)
{
  assert(dbVersion < currentTableVersion());

  TINFO("Migrating from version {} to {}", dbVersion, currentTableVersion());
  switch (dbVersion)
  {
  case 0:
    break;
  default:
    assert(false && "Unreachable code");
    std::terminate();
  }
}
}
}
}
