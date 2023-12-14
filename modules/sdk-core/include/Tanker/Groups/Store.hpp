#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/DataStore/Backend.hpp>
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

  Store(Crypto::SymmetricKey const& userSecret, DataStore::DataStore* db);

  tc::cotask<void> put(Group const& group);

  tc::cotask<std::optional<Group>> findById(Trustchain::GroupId const& groupId) const;
  tc::cotask<std::optional<InternalGroup>> findInternalByPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) const;
  tc::cotask<std::optional<Group>> findByPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) const;

private:
  Crypto::SymmetricKey _userSecret;
  DataStore::DataStore* _db;
};
}
