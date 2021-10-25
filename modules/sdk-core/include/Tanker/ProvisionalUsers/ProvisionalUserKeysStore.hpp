#pragma once

#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Types/ProvisionalUserKeys.hpp>

#include <optional>
#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace DataStore
{
class Database;
}

class ProvisionalUserKeysStore
{
public:
  ProvisionalUserKeysStore(ProvisionalUserKeysStore const&) = delete;
  ProvisionalUserKeysStore(ProvisionalUserKeysStore&&) = delete;
  ProvisionalUserKeysStore& operator=(ProvisionalUserKeysStore const&) = delete;
  ProvisionalUserKeysStore& operator=(ProvisionalUserKeysStore&&) = delete;

  ProvisionalUserKeysStore(DataStore::Database* dbConn);

  tc::cotask<void> putProvisionalUserKeys(
      Crypto::PublicSignatureKey const& appPublicSigKey,
      Crypto::PublicSignatureKey const& tankerPublicSigKey,
      ProvisionalUserKeys const& provisionalUserKeys);
  tc::cotask<std::optional<ProvisionalUserKeys>> findProvisionalUserKeys(
      Crypto::PublicSignatureKey const& appPublicSigKey,
      Crypto::PublicSignatureKey const& tankerPublicSigKey) const;
  tc::cotask<std::optional<Tanker::ProvisionalUserKeys>>
  findProvisionalUserKeysByAppPublicSignatureKey(
      Crypto::PublicSignatureKey const& appPublicSignatureKey) const;

private:
  DataStore::Database* _db;
};
}
