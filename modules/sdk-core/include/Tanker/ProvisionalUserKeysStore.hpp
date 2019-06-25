#pragma once

#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Types/ProvisionalUserKeys.hpp>

#include <optional.hpp>
#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace DataStore
{
class ADatabase;
}

class ProvisionalUserKeysStore
{
public:
  ProvisionalUserKeysStore(ProvisionalUserKeysStore const&) = delete;
  ProvisionalUserKeysStore(ProvisionalUserKeysStore&&) = delete;
  ProvisionalUserKeysStore& operator=(ProvisionalUserKeysStore const&) = delete;
  ProvisionalUserKeysStore& operator=(ProvisionalUserKeysStore&&) = delete;

  ProvisionalUserKeysStore(DataStore::ADatabase* dbConn);

  tc::cotask<void> putProvisionalUserKeys(
      Crypto::PublicSignatureKey const& appPublicSigKey,
      Crypto::PublicSignatureKey const& tankerPublicSigKey,
      ProvisionalUserKeys const& provisionalUserKeys);
  tc::cotask<nonstd::optional<ProvisionalUserKeys>> findProvisionalUserKeys(
      Crypto::PublicSignatureKey const& appPublicSigKey,
      Crypto::PublicSignatureKey const& tankerPublicSigKey) const;
  tc::cotask<nonstd::optional<Tanker::ProvisionalUserKeys>>
  findProvisionalUserKeysByAppPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& appPublicEncryptionKey) const;

private:
  DataStore::ADatabase* _db;
};
}
