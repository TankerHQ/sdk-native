#pragma once

#include <Tanker/ResourceKeys/KeysResult.hpp>

#include <tconcurrent/coroutine.hpp>

#include <gsl-lite.hpp>

#include <memory>
#include <optional>

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
}

namespace Tanker::ResourceKeys
{

class Store
{
public:
  Store(Store const&) = delete;
  Store(Store&&) = delete;
  Store& operator=(Store const&) = delete;
  Store& operator=(Store&&) = delete;

  Store(DataStore::ADatabase* dbConn);

  tc::cotask<void> putKey(Trustchain::ResourceId const& resourceId,
                          Crypto::SymmetricKey const& key);

  tc::cotask<Crypto::SymmetricKey> getKey(
      Trustchain::ResourceId const& resourceId) const;
  tc::cotask<KeysResult> getKeys(
      gsl::span<Trustchain::ResourceId const> resourceIds) const;

  tc::cotask<std::optional<Crypto::SymmetricKey>> findKey(
      Trustchain::ResourceId const& resourceId) const;

private:
  DataStore::ADatabase* _db;
};
}
