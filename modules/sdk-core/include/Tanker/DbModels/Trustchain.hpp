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
  (trustchain)
  ,
  (idx    , int  , SQLPP_PRIMARY_KEY )
  (nature , int  , SQLPP_NOT_NULL    )
  (author , blob , SQLPP_NOT_NULL    )
  (action , blob , SQLPP_NOT_NULL    )
  (hash   , blob , SQLPP_NOT_NULL    )
)
// clang-format on

// namespace created by sqlpp, must place createTable here in order for ADL to
// work.
namespace trustchain
{
void createTable(DataStore::Connection&, trustchain const& = {});
void migrateTable(DataStore::Connection&,
                  int currentVersion,
                  trustchain const& = {});
}
}
}
