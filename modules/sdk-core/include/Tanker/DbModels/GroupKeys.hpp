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
  (group_keys)
  ,
  (public_encryption_key  , blob  , SQLPP_PRIMARY_KEY )
  (private_encryption_key , blob  , SQLPP_NULL        )
  (group_id               , blob  , SQLPP_NOT_NULL    )
)
// clang-format on

// namespace created by sqlpp, must place createTable here in order for ADL to
// work.
namespace group_keys
{
void createTable(DataStore::Connection&, group_keys const& = {});
void migrateTable(DataStore::Connection&,
                  int currentVersion,
                  group_keys const& = {});
}
}
}
