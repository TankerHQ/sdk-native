#include <Tanker/DbModels/ContactDevices.hpp>

#include <Tanker/DataStore/Table.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DbModels/ContactUserKeys.hpp>
#include <Tanker/Types/DeviceId.hpp>

#include <fmt/format.h>

#include <cassert>

namespace Tanker
{
namespace DbModels
{
namespace contact_devices
{
void createTable(DataStore::Connection& db, contact_devices const&)
{
  db.execute(fmt::format(
      fmt(R"(
        CREATE TABLE IF NOT EXISTS contact_devices (
          id BLOB PRIMARY KEY,
          user_id BLOB NOT NULL,
          created_at_block_index INTEGER NOT NULL,
          revoked_at_block_index INTEGER,
          public_signature_key BLOB NOT NULL,
          public_encryption_key BLOB NOT NULL,
          is_ghost_device INTEGER NOT NULL,
          FOREIGN KEY(user_id) REFERENCES {}(user_id)
        );
  )"),
      DataStore::tableName<contact_user_keys::contact_user_keys>()));
}

void migrateTable(DataStore::Connection& db,
                  int dbVersion,
                  contact_devices const&)
{
  assert(dbVersion < currentTableVersion());
}
}
}
}
