#include <Tanker/DbModels/TrustchainIndexes.hpp>

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/Log.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <sqlpp11/sqlpp11.h>

#include <cassert>
#include <exception>

TLOG_CATEGORY(trustchain_indexes);

namespace Tanker
{
namespace DbModels
{
namespace trustchain_indexes
{
namespace
{
void migrate1To2(DataStore::Connection& db)
{
  // we can retrieve BLOB even if stored value was TEXT
  using DataStore::extractBlob;

  trustchain_indexes tab{};
  auto rows = db(select(all_of(tab)).from(tab).unconditionally());
  for (auto const& row : rows)
  {
    auto const hash =
        cppcodec::base64_rfc4648::decode<Crypto::Hash>(extractBlob(row.hash));
    auto const value = cppcodec::base64_rfc4648::decode(extractBlob(row.value));

    db(update(tab)
           .set(tab.hash = hash.base(), tab.value = value)
           .where(tab.id_index == row.id_index));
  }
}
}

void createTable(DataStore::Connection& db, trustchain_indexes const&)
{
  db.execute(R"(
    CREATE TABLE IF NOT EXISTS trustchain_indexes (
      id_index INTEGER PRIMARY KEY,
      hash BLOB NOT NULL,
      type INTEGER NOT NULL,
      value BLOB NOT NULL,
      UNIQUE(type, value, hash)
    );
  )");
}

void migrateTable(DataStore::Connection& db,
                  int dbVersion,
                  trustchain_indexes const&)
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
