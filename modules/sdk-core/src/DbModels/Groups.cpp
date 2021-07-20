#include <Tanker/DbModels/Groups.hpp>

#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DataStore/Version.hpp>
#include <Tanker/Log/Log.hpp>

#include <Tanker/Errors/AssertionError.hpp>

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
      last_key_rotation_block_hash BLOB NOT NULL
    );
  )");
}

void migrateTable(DataStore::Connection& db, int currentVersion, groups const&)
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
    throw Tanker::Errors::AssertionError("Unreachable code");
    std::terminate();
  }
}
}
}
}
