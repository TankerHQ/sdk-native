#include <Tanker/DataStore/ADatabase.hpp>

#include <Tanker/Log/Log.hpp>

TLOG_CATEGORY("ADatabase");

using Tanker::Trustchain::UserId;

namespace Tanker
{
namespace DataStore
{
tc::cotask<void> ADatabase::inTransaction(
    std::function<tc::cotask<void>()> const& f)
{
  TC_AWAIT(startTransaction());
  bool transaction = true;
  std::exception_ptr exc;
  try
  {
    TC_AWAIT(f());
    transaction = false;
    TC_AWAIT(commitTransaction());
  }
  catch (...)
  {
    exc = std::current_exception();
  }
  if (exc)
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
    std::rethrow_exception(exc);
  }
}
}
}
