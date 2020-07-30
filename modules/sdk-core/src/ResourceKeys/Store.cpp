#include <Tanker/ResourceKeys/Store.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/Database.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DbModels/ResourceKeys.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <sqlpp11/sqlite3/insert_or.h>

TLOG_CATEGORY(ResourceKeys::Store);

using Tanker::Trustchain::ResourceId;
using ResourceKeysTable = Tanker::DbModels::resource_keys::resource_keys;

namespace Tanker::ResourceKeys
{
Store::Store(DataStore::Database* dbConn) : _db(dbConn)
{
}

tc::cotask<void> Store::putKey(ResourceId const& resourceId,
                               Crypto::SymmetricKey const& key)
{
  TINFO("Adding key for {}", resourceId);
  FUNC_TIMER(DB);
  ResourceKeysTable tab{};

  (*_db->connection())(sqlpp::sqlite3::insert_or_ignore_into(tab).set(
      tab.mac = resourceId.base(), tab.resource_key = key.base()));
  TC_RETURN();
}

tc::cotask<Crypto::SymmetricKey> Store::getKey(
    ResourceId const& resourceId) const
{
  auto const key = TC_AWAIT(findKey(resourceId));
  if (!key)
  {
    throw Errors::formatEx(Errors::Errc::InvalidArgument,
                           TFMT("key not found for resource {:s}"),
                           resourceId);
  }
  TC_RETURN(*key);
}

tc::cotask<KeysResult> Store::getKeys(
    gsl::span<ResourceId const> resourceIds) const
{
  KeysResult result;
  result.reserve(resourceIds.size());
  for (auto const& resourceId : resourceIds)
    result.emplace_back(
        std::make_tuple(TC_AWAIT(getKey(resourceId)), resourceId));
  TC_RETURN(result);
}

tc::cotask<std::optional<Crypto::SymmetricKey>> Store::findKey(
    ResourceId const& resourceId) const
{
  FUNC_TIMER(DB);
  ResourceKeysTable tab{};
  auto rows = (*_db->connection())(
      select(tab.resource_key).from(tab).where(tab.mac == resourceId.base()));
  if (rows.empty())
    TC_RETURN(std::nullopt);
  auto const& row = rows.front();

  TC_RETURN(DataStore::extractBlob<Crypto::SymmetricKey>(row.resource_key));
}
}
