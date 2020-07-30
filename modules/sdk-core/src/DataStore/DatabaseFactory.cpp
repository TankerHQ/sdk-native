#include <Tanker/DataStore/DatabaseFactory.hpp>

#include <Tanker/DataStore/Database.hpp>

#include <Tanker/Log/Log.hpp>

#include <Tanker/Tracer/ScopeTimer.hpp>

TLOG_CATEGORY("DatabaseFactory");

namespace Tanker
{
namespace DataStore
{
tc::cotask<DatabasePtr> createDatabase(
    std::string const& dbPath,
    std::optional<Crypto::SymmetricKey> const& userSecret,
    bool exclusive)
{
  FUNC_TIMER(DB);
  auto db = std::make_unique<Database>(dbPath, userSecret, exclusive);
  TC_AWAIT(db->migrate());
  TC_RETURN(std::move(db));
}
}
}
