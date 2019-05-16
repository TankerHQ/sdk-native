#include <Tanker/DataStore/Table.hpp>

#include <Tanker/DataStore/Connection.hpp>

#include <sqlpp11/alias_provider.h>
#include <sqlpp11/custom_query.h>
#include <sqlpp11/select.h>
#include <sqlpp11/value.h>
#include <sqlpp11/verbatim.h>

namespace Tanker
{
namespace DataStore
{
namespace detail
{
SQLPP_ALIAS_PROVIDER(count)

bool tableExists(Connection& db, std::string const& tableName)
{
  return db(custom_query(sqlpp::verbatim("SELECT count(*) FROM sqlite_master "
                                         "WHERE type='table' AND name="),
                         tableName)
                .with_result_type_of(select(sqlpp::value(true).as(count))))
      .front()
      .count;
}
}
}
}
