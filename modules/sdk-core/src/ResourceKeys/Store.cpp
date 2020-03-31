#include <Tanker/ResourceKeys/Store.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

TLOG_CATEGORY(ResourceKeys::Store);

using Tanker::Trustchain::ResourceId;

namespace Tanker::ResourceKeys
{
Store::Store(DataStore::ADatabase* dbConn) : _db(dbConn)
{
}

tc::cotask<void> Store::putKey(ResourceId const& resourceId,
                               Crypto::SymmetricKey const& key)
{
  TINFO("Adding key for {}", resourceId);
  TC_AWAIT(_db->putResourceKey(resourceId, key));
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
  TC_RETURN(TC_AWAIT(_db->findResourceKey(resourceId)));
}
}
