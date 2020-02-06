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
  (contact_devices)
  ,
  (id                     , blob  , SQLPP_PRIMARY_KEY )
  (user_id                , blob  , SQLPP_NOT_NULL    )
  (public_signature_key   , blob  , SQLPP_NOT_NULL    )
  (public_encryption_key  , blob  , SQLPP_NOT_NULL    )
  (is_ghost_device        , bool  , SQLPP_NOT_NULL    )
  (is_revoked             , bool  , SQLPP_NOT_NULL    )
)
// clang-format on

// namespace created by sqlpp, must place createTable here in order for ADL to
// work.
namespace contact_devices
{
void createTable(DataStore::Connection&, contact_devices const& = {});
void migrateTable(DataStore::Connection& db,
                  int currentVersion,
                  contact_devices const& = {});
}
}
}
