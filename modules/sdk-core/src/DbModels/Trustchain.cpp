#include <Tanker/DbModels/Trustchain.hpp>

#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Table.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DataStore/Version.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Log/Log.hpp>

#include <cppcodec/base64_rfc4648.hpp>

#include <cassert>
#include <exception>
#include <string>

TLOG_CATEGORY(trustchain);

namespace Tanker
{
namespace DbModels
{
namespace trustchain
{
namespace
{
void renameRecordToAction(DataStore::Connection& db)
{
  auto const name = DataStore::tableName<trustchain>();
  auto const name_orig = name + "_orig";
  db.execute(
      fmt::format(TFMT("ALTER TABLE {:s} RENAME TO {:s}"), name, name_orig));
  createTable(db);
  db.execute(fmt::format(TFMT(R"--(
      INSERT INTO {:s}(idx, nature, author, action, hash)
      SELECT idx, nature, author, record, hash FROM {:s}
    )--"),
                         name,
                         name_orig));
  db.execute(fmt::format("DROP TABLE {}", name_orig));
}

void base64ToBinary(DataStore::Connection& db)
{
  // we can retrieve BLOB even if stored value was TEXT
  using DataStore::extractBlob;

  trustchain tab{};
  auto rows = db(select(all_of(tab)).from(tab).unconditionally());
  for (auto const& row : rows)
  {
    auto const hash = cppcodec::base64_rfc4648::decode(extractBlob(row.hash));
    auto const author =
        cppcodec::base64_rfc4648::decode(extractBlob(row.author));
    auto const action =
        cppcodec::base64_rfc4648::decode(extractBlob(row.action));

    db(update(tab)
           .set(tab.hash = hash, tab.author = author, tab.action = action)
           .where(tab.idx == row.idx));
  }
}

void migrate1To2(DataStore::Connection& db)
{
  renameRecordToAction(db);
  base64ToBinary(db);
}
}
void createTable(DataStore::Connection& db, trustchain const&)
{
  db.execute(R"(
    CREATE TABLE IF NOT EXISTS trustchain (
      idx INTEGER PRIMARY KEY,
      nature INTEGER NOT NULL,
      author BLOB NOT NULL,
      action BLOB NOT NULL,
      hash BLOB NOT NULL UNIQUE
    );
  )");
}

void migrateTable(DataStore::Connection& db,
                  int dbVersion,
                  trustchain const& tab)
{
  assert(dbVersion < DataStore::latestVersion());

  TINFO(
      "Migrating from version {} to {}", dbVersion, DataStore::latestVersion());
  switch (dbVersion)
  {
  case 0:
  case 1:
    migrate1To2(db);
    // fallthrough
  case 2:
    break;
  default:
    assert(false && "Unreachable code");
    std::terminate();
  }
}
}
}
}
