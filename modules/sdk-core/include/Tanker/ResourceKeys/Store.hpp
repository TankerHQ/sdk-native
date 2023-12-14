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

  tc::cotask<void> putKey(Crypto::SimpleResourceId const& resourceId, Crypto::SymmetricKey const& key);

  tc::cotask<Crypto::SymmetricKey> getKey(Crypto::SimpleResourceId const& resourceId) const;

  tc::cotask<std::optional<Crypto::SymmetricKey>> findKey(Crypto::SimpleResourceId const& resourceId) const;

private:
  Crypto::SymmetricKey _userSecret;
  DataStore::DataStore* _db;
};
}
