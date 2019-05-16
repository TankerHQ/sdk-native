#pragma once

#include <sqlpp11/ppgen.h>
#include <sqlpp11/sqlpp11.h>

#include <Tanker/DataStore/Connection.hpp>

namespace Tanker
{
namespace DbModels
{
// clang-format off
// UNIQUE(type, value) cannot be represented with ppgen.
// Not a problem though, it is set by createTable.
SQLPP_DECLARE_TABLE(
  (trustchain_indexes)
  ,
  (id_index , int  , SQLPP_PRIMARY_KEY )
  (hash     , blob , SQLPP_NOT_NULL    )
  (type     , int  , SQLPP_NOT_NULL    )
  (value    , blob , SQLPP_NOT_NULL    )
)
// clang-format on

// namespace created by sqlpp, must place createTable here in order for ADL to
// work.
namespace trustchain_indexes
{
void createTable(DataStore::Connection&, trustchain_indexes const& = {});
void migrateTable(DataStore::Connection&,
                  int currentVersion,
                  trustchain_indexes const& = {});
}
}
}
