#pragma once

#include <tconcurrent/coroutine.hpp>

#include <optional.hpp>

#include <memory>

namespace Tanker
{
namespace Crypto
{
class Mac;
class SymmetricKey;
}

namespace DataStore
{
class ADatabase;
}

class ResourceKeyStore
{
public:
  ResourceKeyStore(ResourceKeyStore const&) = delete;
  ResourceKeyStore(ResourceKeyStore&&) = delete;
  ResourceKeyStore& operator=(ResourceKeyStore const&) = delete;
  ResourceKeyStore& operator=(ResourceKeyStore&&) = delete;

  ResourceKeyStore(DataStore::ADatabase* dbConn);

  tc::cotask<void> putKey(Crypto::Mac const& mac,
                          Crypto::SymmetricKey const& key);
  tc::cotask<nonstd::optional<Crypto::SymmetricKey>> findKey(
      Crypto::Mac const& mac) const;
  tc::cotask<Crypto::SymmetricKey> getKey(Crypto::Mac const& mac) const;

private:
  DataStore::ADatabase* _db;
};
}
