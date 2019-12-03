#pragma once

#include <tconcurrent/coroutine.hpp>

#include <optional>

#include <memory>

namespace Tanker
{
namespace Trustchain
{
class ResourceId;
}

namespace Crypto
{
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

  tc::cotask<void> putKey(Trustchain::ResourceId const& resourceId,
                          Crypto::SymmetricKey const& key);
  tc::cotask<std::optional<Crypto::SymmetricKey>> findKey(
      Trustchain::ResourceId const& resourceId) const;
  tc::cotask<Crypto::SymmetricKey> getKey(
      Trustchain::ResourceId const& resourceId) const;

private:
  DataStore::ADatabase* _db;
};
}
