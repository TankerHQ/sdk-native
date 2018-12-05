
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
  (contact_user_keys)
  ,
  (id                    , int  , SQLPP_PRIMARY_KEY )
  (user_id               , blob , SQLPP_NOT_NULL    )
  (public_encryption_key , blob , SQLPP_NULL        )
)
// clang-format on

// namespace created by sqlpp, must place createTable here in order for ADL to
// work.
namespace contact_user_keys
{
void createTable(DataStore::Connection&, contact_user_keys const& = {});
void migrateTable(DataStore::Connection&,
                  int dbVersion,
                  contact_user_keys const& = {});

constexpr int currentTableVersion(contact_user_keys const& = {})
{
  return 3;
}
}
}
}
