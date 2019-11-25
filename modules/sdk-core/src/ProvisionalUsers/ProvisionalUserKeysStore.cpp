#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>

TLOG_CATEGORY(ResourceKeyStore);

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
  TINFO("Adding provisional user keys for {} {}",
        appPublicSigKey,
        tankerPublicSigKey);
  TC_AWAIT(_db->putProvisionalUserKeys(
      appPublicSigKey, tankerPublicSigKey, provisionalUserKeys));
}

tc::cotask<std::optional<ProvisionalUserKeys>>
ProvisionalUserKeysStore::findProvisionalUserKeys(
    Crypto::PublicSignatureKey const& appPublicSigKey,
    Crypto::PublicSignatureKey const& tankerPublicSigKey) const
{
  TC_RETURN(TC_AWAIT(
      _db->findProvisionalUserKeys(appPublicSigKey, tankerPublicSigKey)));
}

tc::cotask<std::optional<Tanker::ProvisionalUserKeys>>
ProvisionalUserKeysStore::findProvisionalUserKeysByAppPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& appPublicEncryptionKey) const
{

  TC_RETURN(TC_AWAIT(_db->findProvisionalUserKeysByAppPublicEncryptionKey(
      appPublicEncryptionKey)));
}
}
