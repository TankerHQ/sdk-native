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
  (groups)
  ,
  (group_id               , blob  , SQLPP_PRIMARY_KEY )
  (public_signature_key   , blob  , SQLPP_NOT_NULL    )
  (private_signature_key  , blob  , SQLPP_NULL        )
  (encrypted_private_signature_key , blob, SQLPP_NULL )
  (public_encryption_key  , blob  , SQLPP_NOT_NULL    )
  (private_encryption_key , blob  , SQLPP_NULL        )
  (last_group_block_hash  , blob  , SQLPP_NOT_NULL    )
  (last_key_rotation_block_hash , blob  , SQLPP_NOT_NULL )
)
// clang-format on

// namespace created by sqlpp, must place createTable here in order for ADL to
// work.
namespace groups
{
void createTable(DataStore::Connection&, groups const& = {});
void migrateTable(DataStore::Connection&,
                  int currentVersion,
                  groups const& = {});
}
}
}
