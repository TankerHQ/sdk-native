#pragma once

#include <Tanker/Groups/Group.hpp>
#include <Tanker/Trustchain/GroupId.hpp>

#include <optional>

#include <tconcurrent/coroutine.hpp>

namespace Tanker::DataStore
{
class Database;
}

namespace Tanker::Groups
{
class Store
{
public:
  Store(Store const&) = delete;
  Store(Store&&) = delete;
  Store& operator=(Store const&) = delete;
  Store& operator=(Store&&) = delete;

  Store(DataStore::Database* dbConn);

  tc::cotask<void> putKeys(Trustchain::GroupId const& id,
                           std::vector<Crypto::EncryptionKeyPair> const& keys);

  tc::cotask<std::optional<Crypto::EncryptionKeyPair>>
  findKeyByPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) const;

private:
  DataStore::Database* _db;
};
}
