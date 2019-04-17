#include <Tanker/TrustchainStore.hpp>

#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <gsl-lite.hpp>

TLOG_CATEGORY(Trustchain);

namespace Tanker
{
TrustchainStore::TrustchainStore(DataStore::ADatabase* dbConn) : _db(dbConn)
{
}

tc::cotask<void> TrustchainStore::addEntry(Entry const& entry)
{
  TDEBUG("Adding block {}", entry.hash);

  TC_AWAIT(_db->addTrustchainEntry(entry));

  if (entry.index > _lastIndex)
    _lastIndex = entry.index;
}

tc::cotask<nonstd::optional<Entry>> TrustchainStore::findKeyPublish(
    Crypto::Mac const& resourceId) const
{
  TC_RETURN(TC_AWAIT(_db->findTrustchainKeyPublish(resourceId)));
}

tc::cotask<uint64_t> TrustchainStore::getLastIndex()
{
  if (!_lastIndex)
    _lastIndex = TC_AWAIT(_db->getTrustchainLastIndex());
  TC_RETURN(_lastIndex);
}
}
