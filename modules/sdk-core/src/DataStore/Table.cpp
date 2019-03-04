#include <Tanker/DataStore/Table.hpp>

#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DbModels/Versions.hpp>
#include <Tanker/Error.hpp>

#include <sqlpp11/alias_provider.h>
#include <sqlpp11/custom_query.h>
#include <sqlpp11/select.h>
#include <sqlpp11/value.h>
#include <sqlpp11/verbatim.h>

namespace Tanker
{
namespace DataStore
{
namespace detail
{
SQLPP_ALIAS_PROVIDER(count)

bool tableExists(Connection& db, std::string const& tableName)
{
  return db(custom_query(sqlpp::verbatim("SELECT count(*) FROM sqlite_master "
                                         "WHERE type='table' AND name="),
                         tableName)
                .with_result_type_of(select(sqlpp::value(true).as(count))))
      .front()
      .count;
}

nonstd::optional<int> tableVersion(Connection& db, std::string const& tableName)
{
  using VersionsTable = DbModels::versions::versions;
  VersionsTable tab{};

  auto rows = db(select(tab.version).from(tab).where(tab.name == tableName));
  if (rows.empty())
    return nonstd::nullopt;
  return static_cast<int>(rows.front().version);
}

void createOrMigrateTableVersions(Connection& db)
{
  namespace Versions = DbModels::versions;
  using VersionsTable = Versions::versions;

  auto const name = DataStore::tableName<VersionsTable>();
  if (!tableExists(db, name))
    Versions::createTable(db);
  else
  {
    auto const dbVersion = tableVersion(db, name).value();

    if (dbVersion < Versions::currentTableVersion())
      Versions::migrateTable(db, dbVersion);
    else if (dbVersion > Versions::currentTableVersion())
    {
      throw Error::formatEx<Error::MigrationFailed>(
          fmt("database version too recent: {:s}: {:d}"), name, dbVersion);
    }
  }
  detail::updateVersion<VersionsTable>(db);
}
}
}
}
