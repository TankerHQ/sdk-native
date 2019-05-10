#include <Tanker/DbModels/TrustchainLastIndex.hpp>

namespace Tanker
{
namespace DbModels
{
namespace trustchain_last_index
{
void createTable(DataStore::Connection& db, trustchain_last_index const&)
{
  db.execute(R"(
    CREATE TABLE IF NOT EXISTS trustchain_last_index (
      last_index INTEGER NOT NULL
    );
  )");
}

void migrateTable(DataStore::Connection& db,
                  int dbVersion,
                  trustchain_last_index const&)
{
  assert(dbVersion < currentTableVersion());
}
}
}
}
