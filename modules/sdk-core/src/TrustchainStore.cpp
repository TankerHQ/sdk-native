#include <Tanker/TrustchainStore.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <gsl-lite.hpp>

TLOG_CATEGORY(Trustchain);

namespace Tanker
{
TrustchainStore::TrustchainStore(DataStore::ADatabase* dbConn)
  : _db(dbConn), _lastIndex(0)
{
}

tc::cotask<void> TrustchainStore::addEntry(Entry const& entry)
{
  TDEBUG("Adding block {}", entry.hash);

  TC_AWAIT(_db->addTrustchainEntry(entry));
  TC_AWAIT(setLastIndex(entry.index));
}

tc::cotask<void> TrustchainStore::setPublicSignatureKey(
    Crypto::PublicSignatureKey const& key)
{
  TC_AWAIT(_db->setTrustchainPublicSignatureKey(key));
}

tc::cotask<std::optional<Crypto::PublicSignatureKey>>
TrustchainStore::findPublicSignatureKey()
{
  TC_RETURN(TC_AWAIT(_db->findTrustchainPublicSignatureKey()));
}

tc::cotask<uint64_t> TrustchainStore::getLastIndex()
{
  if (!_lastIndex)
    _lastIndex = TC_AWAIT(_db->findTrustchainLastIndex()).value_or(0);
  TC_RETURN(_lastIndex);
}

tc::cotask<void> TrustchainStore::setLastIndex(uint64_t idx)
{
  TC_AWAIT(_db->setTrustchainLastIndex(idx));
  _lastIndex = idx;
  TC_RETURN();
}
}
