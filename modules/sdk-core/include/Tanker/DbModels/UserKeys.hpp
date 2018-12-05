#pragma once

#include <sqlpp11/ppgen.h>
#include <sqlpp11/sqlpp11.h>

#include <Tanker/DataStore/Connection.hpp>

namespace Tanker
{
namespace DbModels
{
// clang-format off
// SQLPP_UNIQUE is not supported... Must add it when creating table.
SQLPP_DECLARE_TABLE(
  (user_keys)
  ,
  (id                     , int   , SQLPP_PRIMARY_KEY )
  (public_encryption_key  , blob  , SQLPP_NOT_NULL    )
  (private_encryption_key , blob  , SQLPP_NOT_NULL    )
)
// clang-format on

// namespace created by sqlpp, must place createTable here in order for ADL to
// work.
namespace user_keys
{
void createTable(DataStore::Connection&, user_keys const& = {});
void migrateTable(DataStore::Connection&, int dbVersion, user_keys const& = {});

constexpr int currentTableVersion(user_keys const& = {})
{
  return 2;
}
}
}
}
