#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/DataStore/Backend.hpp>
#include <Tanker/Utils.hpp>

#include <tconcurrent/coroutine.hpp>

#include <optional>

namespace Tanker
{
namespace DataStore
{
class Database;
}

namespace TransparentSession
{
struct TransparentSessionData
{
  std::uint64_t creationTimestamp;
  Crypto::SimpleResourceId sessionId;
  Crypto::SymmetricKey sessionKey;
};

class Store
{
public:
  Store(Store const&) = delete;
  Store(Store&&) = delete;
  Store& operator=(Store const&) = delete;
  Store& operator=(Store&&) = delete;

  Store(Crypto::SymmetricKey const& userSecret, DataStore::DataStore* db);

  tc::cotask<void> put(Crypto::Hash const& recipientsHash,
                       Crypto::SimpleResourceId const& sessionId,
                       Crypto::SymmetricKey const& sessionKey,
                       std::uint64_t creationTimestamp = secondsSinceEpoch());
  tc::cotask<std::optional<TransparentSessionData>> get(
      Crypto::Hash const& recipientsHash) const;

private:
  Crypto::SymmetricKey _userSecret;
  DataStore::DataStore* _db;
};
}
}
