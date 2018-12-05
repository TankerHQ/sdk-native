#include <Tanker/DbModels/Groups.hpp>

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Crypto/base64.hpp>
#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/Log.hpp>

#include <cassert>
#include <exception>

TLOG_CATEGORY(groups);

namespace Tanker
{
namespace DbModels
{
namespace groups
{
void createTable(DataStore::Connection& db, groups const&)
{
  db.execute(R"(
    CREATE TABLE IF NOT EXISTS groups (
      group_id BLOB PRIMARY KEY,
      public_signature_key BLOB NOT NULL UNIQUE,
      private_signature_key BLOB NULL,
      encrypted_private_signature_key BLOB NULL,
      public_encryption_key BLOB NOT NULL UNIQUE,
      private_encryption_key BLOB NULL,
      last_group_block_hash BLOB NOT NULL,
      last_group_block_index INTEGER NOT NULL
    );
  )");
}

void migrateTable(DataStore::Connection& db, int dbVersion, groups const&)
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
