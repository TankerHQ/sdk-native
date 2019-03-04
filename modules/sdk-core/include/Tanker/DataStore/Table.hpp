#pragma once

#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DbModels/Versions.hpp>
#include <Tanker/Error.hpp>

#include <fmt/format.h>
#include <optional.hpp>
#include <sqlpp11/char_sequence.h>
#include <sqlpp11/sqlite3/insert_or.h>
#include <sqlpp11/transaction.h>
#include <sqlpp11/type_traits.h>

#include <string>

namespace Tanker
{
namespace DataStore
{
namespace detail
{
template <typename T>
struct tableName;

template <char... Cs>
struct tableName<sqlpp::char_sequence<Cs...>>
{
  static std::string get()
  {
    return {{Cs...}};
  }
};

template <typename Table>
void updateVersion(Connection& db)
{
  using VersionsTable = DbModels::versions::versions;

  VersionsTable tab{};

  auto const name = tableName<sqlpp::name_of<Table>>::get();
  auto const version = currentTableVersion(Table{});

  db(sqlpp::sqlite3::insert_or_replace_into(tab).set(tab.name = name,
                                                     tab.version = version));
}

bool tableExists(Connection&, std::string const&);
nonstd::optional<int> tableVersion(Connection&, std::string const&);
void createOrMigrateTableVersions(Connection&);
}

template <typename Table>
std::string tableName()
{
  return detail::tableName<sqlpp::name_of<Table>>::get();
}

template <typename Table>
bool tableExists(Connection& db)
{
  auto const name = tableName<Table>();
  return detail::tableExists(db, name);
}

template <typename Table>
nonstd::optional<int> tableVersion(Connection& db)
{
  auto const name = tableName<Table>();
  return detail::tableVersion(db, name);
}

template <typename Table>
void createOrMigrateTable(Connection& db);

template <>
void createOrMigrateTable<DbModels::versions::versions>(Connection& db) =
    delete;

template <typename Table>
void createOrMigrateTable(Connection& db)
{
  Table const tab{};

  auto tr = sqlpp::start_transaction(db);

  detail::createOrMigrateTableVersions(db);

  if (!tableExists<Table>(db))
    createTable(db, tab);
  else
  {
    // Some tables were created before versions were implemented
    // Default to value 0
    auto const dbVersion = tableVersion<Table>(db).value_or(0);
    if (dbVersion < currentTableVersion(tab))
      migrateTable(db, dbVersion, tab);
    else if (dbVersion > currentTableVersion(tab))
    {
      throw Error::formatEx<Error::MigrationFailed>(
          fmt("database version too recent: {:s}: {:d}"),
          tableName<Table>(),
          dbVersion);
    }
  }
  detail::updateVersion<Table>(db);
  tr.commit();
}
}
}
