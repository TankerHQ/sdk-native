#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/DataStore/Backend.hpp>
#include <Tanker/ResourceKeys/KeysResult.hpp>

#include <tconcurrent/coroutine.hpp>

#include <gsl/gsl-lite.hpp>

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

  Store(Crypto::SymmetricKey const& userSecret, DataStore::DataStore* db);

  tc::cotask<void> putKey(Trustchain::ResourceId const& resourceId,
                          Crypto::SymmetricKey const& key);

  tc::cotask<Crypto::SymmetricKey> getKey(
      Trustchain::ResourceId const& resourceId) const;

  tc::cotask<std::optional<Crypto::SymmetricKey>> findKey(
      Trustchain::ResourceId const& resourceId) const;

private:
  Crypto::SymmetricKey _userSecret;
  DataStore::DataStore* _db;
};
}
