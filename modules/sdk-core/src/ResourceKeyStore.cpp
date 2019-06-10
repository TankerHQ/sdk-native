#include <Tanker/ResourceKeyStore.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <fmt/format.h>

TLOG_CATEGORY(ResourceKeyStore);

using Tanker::Trustchain::ResourceId;

namespace Tanker
{
ResourceKeyStore::ResourceKeyStore(DataStore::ADatabase* dbConn) : _db(dbConn)
{
}

tc::cotask<void> ResourceKeyStore::putKey(ResourceId const& resourceId,
                                          Crypto::SymmetricKey const& key)
{
  TINFO("Adding key for {}", resourceId);
  TC_AWAIT(_db->putResourceKey(resourceId, key));
}

tc::cotask<Crypto::SymmetricKey> ResourceKeyStore::getKey(
    ResourceId const& resourceId) const
{
  auto const key = TC_AWAIT(findKey(resourceId));
  if (!key)
  {
    throw Errors::formatEx(Errors::Errc::NotFound,
                           "key not found for resource {}",
                           resourceId);
  }
  TC_RETURN(*key);
}

tc::cotask<nonstd::optional<Crypto::SymmetricKey>> ResourceKeyStore::findKey(
    ResourceId const& resourceId) const
{
  TC_RETURN(TC_AWAIT(_db->findResourceKey(resourceId)));
}
}
