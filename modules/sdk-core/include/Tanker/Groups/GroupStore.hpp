#pragma once

#include <Tanker/Groups/Group.hpp>
#include <Tanker/Trustchain/GroupId.hpp>

#include <optional.hpp>
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
  tc::cotask<void> put(ExternalGroup const& group);
  tc::cotask<void> updateLastGroupBlock(Trustchain::GroupId const& groupId,
                                        Crypto::Hash const& lastBlockHash,
                                        uint64_t lastBlockIndex);

  tc::cotask<nonstd::optional<Group>> findFullById(
      Trustchain::GroupId const& groupId) const;
  tc::cotask<nonstd::optional<ExternalGroup>> findExternalById(
      Trustchain::GroupId const& groupId) const;
  tc::cotask<nonstd::optional<Group>> findFullByPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) const;
  tc::cotask<nonstd::optional<ExternalGroup>> findExternalByPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) const;

private:
  DataStore::ADatabase* _db;
};
}
