#include <Tanker/DbModels/GroupsProvisionalEncryptionKeys.hpp>

#include <Tanker/Log.hpp>

#include <cassert>

TLOG_CATEGORY(group_provisional_encryption_keys);

namespace Tanker
{
namespace DbModels
{
namespace group_provisional_encryption_keys
{
void createTable(DataStore::Connection& db,
                 group_provisional_encryption_keys const&)
{
  db.execute(R"(
    CREATE TABLE IF NOT EXISTS group_provisional_encryption_keys (
      app_public_signature_key BLOB NOT NULL,
      tanker_public_signature_key BLOB NOT NULL,
      group_id BLOB NOT NULL,
      encrypted_private_encryption_key BLOB NOT NULL,
      PRIMARY KEY(app_public_signature_key, tanker_public_signature_key, group_id)
    );
  )");
}
}
}
}

