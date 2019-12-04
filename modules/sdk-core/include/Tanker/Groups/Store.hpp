#pragma once

#include <Tanker/Groups/Group.hpp>
#include <Tanker/Trustchain/GroupId.hpp>

#include <optional>
#include <tconcurrent/coroutine.hpp>

namespace Tanker::DataStore
{
class ADatabase;
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

  Store(DataStore::ADatabase* dbConn);

  tc::cotask<void> put(Group const& group);
  tc::cotask<void> put(InternalGroup const& group);
  tc::cotask<void> put(ExternalGroup const& group);

  tc::cotask<std::optional<Group>> findById(
      Trustchain::GroupId const& groupId) const;
  tc::cotask<std::optional<InternalGroup>> findInternalByPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) const;
  tc::cotask<std::optional<Group>> findByPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) const;

private:
  DataStore::ADatabase* _db;
};
}
