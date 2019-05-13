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
  (key_publishes)
  ,
  (resource_id  , blob , SQLPP_PRIMARY_KEY )
  (nature       , int  , SQLPP_NOT_NULL    )
  (recipient    , blob , SQLPP_NOT_NULL    )
  (key          , blob , SQLPP_NOT_NULL    )
)
// clang-format on

// namespace created by sqlpp, must place createTable here in order for ADL to
// work.
namespace key_publishes
{
void createTable(DataStore::Connection&, key_publishes const& = {});
void migrateTable(DataStore::Connection&,
                  int dbVersion,
                  key_publishes const& = {});

constexpr int currentTableVersion(key_publishes const& = {})
{
  return 1;
}
}
}
}
