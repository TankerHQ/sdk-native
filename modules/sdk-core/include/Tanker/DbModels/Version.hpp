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
  (version)
  ,
  (db_version, int, SQLPP_NOT_NULL)
)
// clang-format on

// namespace created by sqlpp, must place createTable here in order for ADL to
// work.
namespace version
{
void createTable(DataStore::Connection&, version const& = {});
}
}
}
