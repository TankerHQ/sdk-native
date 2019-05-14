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
  (group_provisional_encryption_keys)
  ,
  (group_id                         , blob , SQLPP_NOT_NULL )
  (app_public_signature_key         , blob , SQLPP_NOT_NULL )
  (tanker_public_signature_key      , blob , SQLPP_NOT_NULL )
  (encrypted_private_encryption_key , blob , SQLPP_NOT_NULL )
)
// clang-format on

// namespace created by sqlpp, must place createTable here in order for ADL to
// work.
namespace group_provisional_encryption_keys
{
void createTable(DataStore::Connection&,
                 group_provisional_encryption_keys const& = {});
void migrateTable(DataStore::Connection&,
                  int dbVersion,
                  group_provisional_encryption_keys const& = {});

constexpr int currentTableVersion(
    group_provisional_encryption_keys const& = {})
{
  return 1;
}
}
}
}
