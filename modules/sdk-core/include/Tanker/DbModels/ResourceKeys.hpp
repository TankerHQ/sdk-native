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
  (resource_keys)
  ,
  (id           , int  , SQLPP_PRIMARY_KEY )
  (mac          , blob , SQLPP_NOT_NULL    )
  (resource_key , blob , SQLPP_NOT_NULL    )
)
// clang-format on

// namespace created by sqlpp, must place createTable here in order for ADL to
// work.
namespace resource_keys
{
void createTable(DataStore::Connection&, resource_keys const& = {});
void migrateTable(DataStore::Connection&,
                  int currentVersion,
                  resource_keys const& = {});
}
}
}
