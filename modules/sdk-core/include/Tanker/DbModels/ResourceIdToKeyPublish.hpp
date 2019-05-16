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
  (resource_id_to_key_publish)
  ,
  (resource_id , blob  , SQLPP_PRIMARY_KEY )
  (hash        , blob  , SQLPP_NOT_NULL    )
)
// clang-format on

// namespace created by sqlpp, must place createTable here in order for ADL to
// work.
namespace resource_id_to_key_publish
{
void createTable(DataStore::Connection&,
                 resource_id_to_key_publish const& = {});
void migrateTable(DataStore::Connection&,
                  int currentVersion,
                  resource_id_to_key_publish const& = {});
}
}
}
