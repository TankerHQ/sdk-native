#include <Tanker/ResourceKeyStore.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/ResourceKeyNotFound.hpp>

TLOG_CATEGORY(ResourceKeyStore);

namespace Tanker
{
ResourceKeyStore::ResourceKeyStore(DataStore::ADatabase* dbConn) : _db(dbConn)
{
}

tc::cotask<void> ResourceKeyStore::putKey(Crypto::Mac const& mac,
                                          Crypto::SymmetricKey const& key)
{
  TINFO("Adding key for {}", mac);
  TC_AWAIT(_db->putResourceKey(mac, key));
}

tc::cotask<Crypto::SymmetricKey> ResourceKeyStore::getKey(
    Crypto::Mac const& mac) const
{
  auto const key = TC_AWAIT(findKey(mac));
  if (!key)
    throw Error::ResourceKeyNotFound(mac);
  TC_RETURN(*key);
}

tc::cotask<nonstd::optional<Crypto::SymmetricKey>> ResourceKeyStore::findKey(
    Crypto::Mac const& mac) const
{
  TC_RETURN(TC_AWAIT(_db->findResourceKey(mac)));
}
}
