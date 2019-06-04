#pragma once

#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Version.hpp>
#include <Tanker/DbModels/Version.hpp>
#include <Tanker/Error.hpp>

#include <optional.hpp>
#include <sqlpp11/char_sequence.h>
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

bool tableExists(Connection&, std::string const&);
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
void createTable(Connection& db)
{
  Table const tab{};

  createTable(db, tab);
}

template <typename Table>
void migrateTable(Connection& db, int currentVersion)
{
  Table const tab{};

  migrateTable(db, currentVersion, tab);
}
}
}
