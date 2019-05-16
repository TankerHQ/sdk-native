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
  (provisional_user_keys)
  ,
  (app_pub_sig_key      , blob , SQLPP_PRIMARY_KEY)
  (tanker_pub_sig_key   , blob , SQLPP_PRIMARY_KEY)
  (app_enc_pub          , blob , SQLPP_NOT_NULL   )
  (app_enc_priv         , blob , SQLPP_NOT_NULL   )
  (tanker_enc_pub       , blob , SQLPP_NOT_NULL   )
  (tanker_enc_priv      , blob , SQLPP_NOT_NULL   )
)
// clang-format on

namespace provisional_user_keys
{
void createTable(DataStore::Connection&, provisional_user_keys const& = {});
}
}
}
