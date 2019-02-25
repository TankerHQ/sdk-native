#include <Tanker/DbModels/ResourceKeys.hpp>

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Crypto/base64.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/Log.hpp>

#include <cassert>
#include <exception>

TLOG_CATEGORY(resource_keys);

namespace Tanker
{
namespace DbModels
{
namespace resource_keys
{
namespace
{
void migrate1To2(DataStore::Connection& db)
{
  using DataStore::extractBlob;

  resource_keys tab{};
  auto rows = db(select(all_of(tab)).from(tab).unconditionally());
  for (auto const& row : rows)
  {
    auto const mac = base64::decode<Crypto::Mac>(extractBlob(row.mac));
    auto const resourceKey =
        base64::decode<Crypto::SymmetricKey>(extractBlob(row.resource_key));

    db(update(tab)
           .set(tab.mac = mac.base(), tab.resource_key = resourceKey.base())
           .where(tab.id == row.id));
  }
}
}

void createTable(DataStore::Connection& db, resource_keys const&)
{
  db.execute(R"(
    CREATE TABLE IF NOT EXISTS resource_keys (
      id INTEGER PRIMARY KEY,
      mac BLOB NOT NULL,
      resource_key BLOB NOT NULL
    );
  )");
}

void migrateTable(DataStore::Connection& db,
                  int dbVersion,
                  resource_keys const&)
{
  assert(dbVersion < currentTableVersion());

  TINFO("Migrating from version {} to {}", dbVersion, currentTableVersion());
  switch (dbVersion)
  {
  case 0:
  case 1:
    migrate1To2(db);
    break;
  default:
    assert(false && "Unreachable code");
    std::terminate();
  }
}
}
}
}
