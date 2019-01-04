#include <Tanker/DataStore/ADatabase.hpp>

#ifndef EMSCRIPTEN
#include <Tanker/DataStore/Database.hpp>
#else
#include <Tanker/DataStore/JsDatabase.hpp>
#endif

#include <Tanker/Log.hpp>

#include <Tanker/Tracer/ScopeTimer.hpp>

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

tc::cotask<DatabasePtr> createDatabase(
    std::string const& dbPath,
    nonstd::optional<Crypto::SymmetricKey> const& userSecret,
    bool exclusive)
{
  FUNC_TIMER(DB);
#ifndef EMSCRIPTEN
  TC_RETURN(std::make_unique<Database>(dbPath, userSecret, exclusive));
#else
  auto db = std::make_unique<JsDatabase>();
  TC_AWAIT(db->open(dbPath));
  TC_RETURN(std::move(db));
#endif
}
}
}
