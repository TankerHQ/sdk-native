#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/Database.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DbModels/ProvisionalUserKeys.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>

#include <sqlpp11/sqlite3/insert_or.h>

TLOG_CATEGORY(ProvisionalUserKeysStore);

using ProvisionalUserKeysTable =
    Tanker::DbModels::provisional_user_keys::provisional_user_keys;

namespace Tanker
{
ProvisionalUserKeysStore::ProvisionalUserKeysStore(DataStore::Database* dbConn)
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
  FUNC_TIMER(DB);
  ProvisionalUserKeysTable tab;

  (*_db->connection())(sqlpp::sqlite3::insert_or_ignore_into(tab).set(
      tab.app_pub_sig_key = appPublicSigKey.base(),
      tab.tanker_pub_sig_key = tankerPublicSigKey.base(),
      tab.app_enc_priv = provisionalUserKeys.appKeys.privateKey.base(),
      tab.app_enc_pub = provisionalUserKeys.appKeys.publicKey.base(),
      tab.tanker_enc_priv = provisionalUserKeys.tankerKeys.privateKey.base(),
      tab.tanker_enc_pub = provisionalUserKeys.tankerKeys.publicKey.base()));
  TC_RETURN();
}

tc::cotask<std::optional<ProvisionalUserKeys>>
ProvisionalUserKeysStore::findProvisionalUserKeys(
    Crypto::PublicSignatureKey const& appPublicSigKey,
    Crypto::PublicSignatureKey const& tankerPublicSigKey) const
{
  FUNC_TIMER(DB);
  ProvisionalUserKeysTable tab{};
  auto rows = (*_db->connection())(
      select(tab.app_enc_priv,
             tab.app_enc_pub,
             tab.tanker_enc_priv,
             tab.tanker_enc_pub)
          .from(tab)
          .where(tab.app_pub_sig_key == appPublicSigKey.base() and
                 tab.tanker_pub_sig_key == tankerPublicSigKey.base()));
  if (rows.empty())
    TC_RETURN(std::nullopt);
  auto const& row = rows.front();
  Tanker::ProvisionalUserKeys ret{
      {DataStore::extractBlob<Crypto::PublicEncryptionKey>(row.app_enc_pub),
       DataStore::extractBlob<Crypto::PrivateEncryptionKey>(row.app_enc_priv)},
      {DataStore::extractBlob<Crypto::PublicEncryptionKey>(row.tanker_enc_pub),
       DataStore::extractBlob<Crypto::PrivateEncryptionKey>(
           row.tanker_enc_priv)}};
  TC_RETURN(ret);
}

tc::cotask<std::optional<Tanker::ProvisionalUserKeys>>
ProvisionalUserKeysStore::findProvisionalUserKeysByAppPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& appPublicEncryptionKey) const
{
  FUNC_TIMER(DB);
  ProvisionalUserKeysTable tab{};
  auto rows = (*_db->connection())(
      select(tab.app_enc_priv,
             tab.app_enc_pub,
             tab.tanker_enc_priv,
             tab.tanker_enc_pub)
          .from(tab)
          .where(tab.app_enc_pub == appPublicEncryptionKey.base()));
  if (rows.empty())
    TC_RETURN(std::nullopt);
  auto const& row = rows.front();
  Tanker::ProvisionalUserKeys ret{
      {DataStore::extractBlob<Crypto::PublicEncryptionKey>(row.app_enc_pub),
       DataStore::extractBlob<Crypto::PrivateEncryptionKey>(row.app_enc_priv)},
      {DataStore::extractBlob<Crypto::PublicEncryptionKey>(row.tanker_enc_pub),
       DataStore::extractBlob<Crypto::PrivateEncryptionKey>(
           row.tanker_enc_priv)}};
  TC_RETURN(ret);
}
}
