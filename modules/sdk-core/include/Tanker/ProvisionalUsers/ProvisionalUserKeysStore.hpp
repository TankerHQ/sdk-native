#pragma once

#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/DataStore/Backend.hpp>
#include <Tanker/Types/ProvisionalUserKeys.hpp>

#include <optional>
#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
class ProvisionalUserKeysStore
{
public:
  ProvisionalUserKeysStore(ProvisionalUserKeysStore const&) = delete;
  ProvisionalUserKeysStore(ProvisionalUserKeysStore&&) = delete;
  ProvisionalUserKeysStore& operator=(ProvisionalUserKeysStore const&) = delete;
  ProvisionalUserKeysStore& operator=(ProvisionalUserKeysStore&&) = delete;

  ProvisionalUserKeysStore(Crypto::SymmetricKey const& userSecret, DataStore::DataStore* db);

  tc::cotask<void> putProvisionalUserKeys(Crypto::PublicSignatureKey const& appPublicSigKey,
                                          Crypto::PublicSignatureKey const& tankerPublicSigKey,
                                          ProvisionalUserKeys const& provisionalUserKeys);
  tc::cotask<std::optional<ProvisionalUserKeys>> findProvisionalUserKeys(
      Crypto::PublicSignatureKey const& appPublicSigKey, Crypto::PublicSignatureKey const& tankerPublicSigKey) const;
  tc::cotask<std::optional<Tanker::ProvisionalUserKeys>> findProvisionalUserKeysByAppPublicSignatureKey(
      Crypto::PublicSignatureKey const& appPublicSignatureKey) const;

private:
  Crypto::SymmetricKey _userSecret;
  DataStore::DataStore* _db;
};
}
