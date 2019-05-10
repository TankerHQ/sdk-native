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
  (trustchain_info)
  ,
  (last_index, int, SQLPP_NOT_NULL)
  (trustchain_public_signature_key, blob, SQLPP_NULL)
)
// clang-format on

// namespace created by sqlpp, must place createTable here in order for ADL to
// work.
namespace trustchain_info
{
void createTable(DataStore::Connection&, trustchain_info const& = {});
void migrateTable(DataStore::Connection&,
                  int dbVersion,
                  trustchain_info const& = {});

constexpr int currentTableVersion(trustchain_info const& = {})
{
  return 1;
}
}
}
}
