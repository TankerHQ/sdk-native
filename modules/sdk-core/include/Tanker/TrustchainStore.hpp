#pragma once

#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <tconcurrent/coroutine.hpp>

#include <optional>

#include <cstdint>
#include <vector>

namespace Tanker
{

struct Entry;

namespace DataStore
{
class ADatabase;
}

class TrustchainStore
{
public:
  TrustchainStore(DataStore::ADatabase* dbConn);
  TrustchainStore(TrustchainStore const&) = delete;
  TrustchainStore(TrustchainStore&&) = delete;
  TrustchainStore& operator=(TrustchainStore const&) = delete;
  TrustchainStore& operator=(TrustchainStore&&) = delete;

  tc::cotask<void> addEntry(Entry const& entry);
  tc::cotask<void> setPublicSignatureKey(Crypto::PublicSignatureKey const&);
  tc::cotask<std::optional<Crypto::PublicSignatureKey>>
  findPublicSignatureKey();

  tc::cotask<uint64_t> getLastIndex();
  tc::cotask<void> setLastIndex(uint64_t);

private:
  DataStore::ADatabase* _db;
  uint64_t _lastIndex;
};
}
