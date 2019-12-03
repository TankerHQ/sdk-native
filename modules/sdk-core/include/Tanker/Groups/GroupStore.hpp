#pragma once

#include <Tanker/Groups/Group.hpp>
#include <Tanker/Trustchain/GroupId.hpp>

#include <optional>
#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace DataStore
{
class ADatabase;
}

class GroupStore
{
public:
  GroupStore(GroupStore const&) = delete;
  GroupStore(GroupStore&&) = delete;
  GroupStore& operator=(GroupStore const&) = delete;
  GroupStore& operator=(GroupStore&&) = delete;

  GroupStore(DataStore::ADatabase* dbConn);

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
