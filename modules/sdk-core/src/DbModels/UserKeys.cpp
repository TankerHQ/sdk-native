#include <Tanker/DbModels/UserKeys.hpp>

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Crypto/base64.hpp>
#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/Log.hpp>

#include <cassert>
#include <exception>

TLOG_CATEGORY(user_keys);

namespace Tanker
{
namespace DbModels
{
namespace user_keys
{
namespace
{
void migrate1To2(DataStore::Connection& db)
{
  using DataStore::extractBlob;

  user_keys tab{};
  auto rows = db(select(all_of(tab)).from(tab).unconditionally());
  for (auto const& row : rows)
  {
    auto const pubK = base64::decode<Crypto::PublicEncryptionKey>(
        extractBlob(row.public_encryption_key));
    auto const privK = base64::decode<Crypto::PrivateEncryptionKey>(
        extractBlob(row.private_encryption_key));

    db(update(tab)
           .set(tab.public_encryption_key = pubK.base(),
                tab.private_encryption_key = privK.base())
           .where(tab.id == row.id));
  }
}
}

void createTable(DataStore::Connection& db, user_keys const&)
{
  db.execute(R"(
    CREATE TABLE IF NOT EXISTS user_keys (
      id INTEGER PRIMARY KEY,
      public_encryption_key BLOB NOT NULL UNIQUE,
      private_encryption_key BLOB NOT NULL
    );
  )");
}

void migrateTable(DataStore::Connection& db, int dbVersion, user_keys const&)
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
