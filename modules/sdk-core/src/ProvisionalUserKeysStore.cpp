#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/ProvisionalUserKeysStore.hpp>

namespace Tanker
{
ProvisionalUserKeysStore::ProvisionalUserKeysStore(DataStore::ADatabase* dbConn)
  : _db(dbConn)
{
}

tc::cotask<void> ProvisionalUserKeysStore::putProvisionalUserKeys(
    Crypto::PublicSignatureKey const& appPublicSigKey,
    Crypto::PublicSignatureKey const& tankerPublicSigKey,
    ProvisionalUserKeys const& provisionalUserKeys)
{
  TC_AWAIT(_db->putProvisionalUserKeys(
      appPublicSigKey, tankerPublicSigKey, provisionalUserKeys));
}

tc::cotask<nonstd::optional<ProvisionalUserKeys>>
ProvisionalUserKeysStore::findProvisionalUserKeys(
    Crypto::PublicSignatureKey const& appPublicSigKey,
    Crypto::PublicSignatureKey const& tankerPublicSigKey) const
{
  TC_RETURN(TC_AWAIT(
      _db->findProvisionalUserKeys(appPublicSigKey, tankerPublicSigKey)));
}
}
