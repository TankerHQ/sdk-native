#pragma once

#include <sqlpp11/ppgen.h>
#include <sqlpp11/sqlpp11.h>

#include <Tanker/DataStore/Connection.hpp>

namespace Tanker
{
namespace DbModels
{
// clang-format off
SQLPP_DECLARE_TABLE(
  (trustchain_last_index)
  ,
  (last_index, int, SQLPP_NOT_NULL)
)
// clang-format on

// namespace created by sqlpp, must place createTable here in order for ADL to
// work.
namespace trustchain_last_index
{
void createTable(DataStore::Connection&, trustchain_last_index const& = {});
void migrateTable(DataStore::Connection&,
                  int dbVersion,
                  trustchain_last_index const& = {});

constexpr int currentTableVersion(trustchain_last_index const& = {})
{
  return 1;
}
}
}
}
