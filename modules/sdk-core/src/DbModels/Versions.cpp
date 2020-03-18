#include <Tanker/DbModels/Versions.hpp>

#include <Tanker/DataStore/Connection.hpp>

namespace Tanker
{
namespace DbModels
{
namespace versions
{
void createTable(DataStore::Connection& db, versions const&)
{
  db.execute(R"(
    CREATE TABLE IF NOT EXISTS versions (
      name TEXT PRIMARY KEY,
      version INTEGER NOT NULL
    );
  )");
}
}
}
}
