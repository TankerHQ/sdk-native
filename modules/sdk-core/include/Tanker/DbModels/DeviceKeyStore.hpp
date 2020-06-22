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
  (device_key_store)
  ,
  (id                     , int  , SQLPP_PRIMARY_KEY )
  (private_signature_key  , blob , SQLPP_NOT_NULL    )
  (public_signature_key   , blob , SQLPP_NOT_NULL    )
  (private_encryption_key , blob , SQLPP_NOT_NULL    )
  (public_encryption_key  , blob , SQLPP_NOT_NULL    )
  (device_id              , blob                     )
  (device_initialized     , int                      )
)
// clang-format on

// namespace created by sqlpp, must place createTable here in order for ADL to
// work.
namespace device_key_store
{
void createTable(DataStore::Connection&, device_key_store const& = {});
void migrateTable(DataStore::Connection& db,
                  int currentVersion,
                  device_key_store const& = {});
}
}
}
