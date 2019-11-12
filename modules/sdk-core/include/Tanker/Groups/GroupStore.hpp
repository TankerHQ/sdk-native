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
  tc::cotask<void> put(InternalGroup const& group);
  tc::cotask<void> put(ExternalGroup const& group);
  tc::cotask<void> putGroupProvisionalEncryptionKeys(
      Trustchain::GroupId const& groupId,
      std::vector<GroupProvisionalUser> const& provisionalUsers);
  tc::cotask<void> updateLastGroupBlock(Trustchain::GroupId const& groupId,
                                        Crypto::Hash const& lastBlockHash,
                                        uint64_t lastBlockIndex);

  tc::cotask<nonstd::optional<InternalGroup>> findInternalById(
      Trustchain::GroupId const& groupId) const;
  tc::cotask<nonstd::optional<ExternalGroup>> findExternalById(
      Trustchain::GroupId const& groupId) const;
  tc::cotask<nonstd::optional<InternalGroup>> findInternalByPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) const;
  tc::cotask<nonstd::optional<ExternalGroup>> findExternalByPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) const;
  tc::cotask<std::vector<ExternalGroup>> findExternalGroupsByProvisionalUser(
      Crypto::PublicSignatureKey const& appPublicSignatureKey,
      Crypto::PublicSignatureKey const& tankerPublicSignatureKey) const;

private:
  DataStore::ADatabase* _db;
};
}
