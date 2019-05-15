#include <Tanker/DbModels/TrustchainInfo.hpp>

namespace Tanker
{
namespace DbModels
{
namespace trustchain_info
{
void createTable(DataStore::Connection& db, trustchain_info const&)
{
  db.execute(R"(
    CREATE TABLE IF NOT EXISTS trustchain_info (
      last_index INTEGER NOT NULL,
      trustchain_public_signature_key BLOB
    );
  )");
  db.execute(R"(
    INSERT INTO trustchain_info VALUES (0, NULL)
  )");
}

void migrateTable(DataStore::Connection& db,
                  int dbVersion,
                  trustchain_info const&)
{
  assert(dbVersion < currentTableVersion());
}
}
}
}
