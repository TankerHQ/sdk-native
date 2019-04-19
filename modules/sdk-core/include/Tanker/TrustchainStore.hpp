#pragma once

#include <Tanker/Trustchain/UserId.hpp>

#include <tconcurrent/coroutine.hpp>

#include <optional.hpp>

#include <cstdint>
#include <vector>

namespace Tanker
{
namespace Crypto
{
class Mac;
}

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

  tc::cotask<nonstd::optional<Entry>> findKeyPublish(
      Crypto::Mac const& resourceId) const;

  tc::cotask<uint64_t> getLastIndex();

private:
  DataStore::ADatabase* _db;

  uint64_t _lastIndex = 0;
};
}
