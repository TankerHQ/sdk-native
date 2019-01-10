#include <Tanker/DataStore/ADatabase.hpp>

#include <Tanker/Log.hpp>

TLOG_CATEGORY("ADatabase");

namespace Tanker
{
namespace DataStore
{
tc::cotask<void> ADatabase::inTransaction(
    std::function<tc::cotask<void>()> const& f)
{
  TC_AWAIT(startTransaction());
  bool transaction = true;
  try
  {
    TC_AWAIT(f());
    transaction = false;
    TC_AWAIT(commitTransaction());
  }
  catch (...)
  {
    if (transaction)
    {
      try
      {
        TC_AWAIT(rollbackTransaction());
      }
      catch (std::exception const& e)
      {
        TERROR("Failed to rollback transaction: {}", e.what());
      }
      catch (...)
      {
        TERROR("Failed to rollback transaction: unknown error");
      }
    }
    throw;
  }
}
}
}
