#pragma once

#include <Tanker/Groups/Group.hpp>
#include <Tanker/Types/GroupId.hpp>

#include <optional.hpp>
#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace DataStore
{
class Database;
}

class GroupStore
{
public:
  GroupStore(GroupStore const&) = delete;
  GroupStore(GroupStore&&) = delete;
  GroupStore& operator=(GroupStore const&) = delete;
  GroupStore& operator=(GroupStore&&) = delete;

  GroupStore(DataStore::Database* dbConn);

  tc::cotask<void> put(Group const& group);
  tc::cotask<void> put(ExternalGroup const& group);
  tc::cotask<void> updateLastGroupBlock(GroupId const& groupId,
                                        Crypto::Hash const& lastBlockHash,
                                        uint64_t lastBlockIndex);

  tc::cotask<nonstd::optional<Group>> findFullById(
      GroupId const& groupId) const;
  tc::cotask<nonstd::optional<ExternalGroup>> findExternalById(
      GroupId const& groupId) const;
  tc::cotask<nonstd::optional<Group>> findFullByPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) const;
  tc::cotask<nonstd::optional<ExternalGroup>> findExternalByPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) const;

private:
  DataStore::Database* _db;
};
}
