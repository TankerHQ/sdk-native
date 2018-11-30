#include <Tanker/Groups/GroupStore.hpp>

#include <Tanker/Crypto/KeyFormat.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Log.hpp>

#include <optional.hpp>
#include <tconcurrent/coroutine.hpp>

TLOG_CATEGORY(GroupStore);

namespace Tanker
{
GroupStore::GroupStore(DataStore::ADatabase* dbConn) : _db(dbConn)
{
}

tc::cotask<void> GroupStore::put(Group const& group)
{
  TINFO("Adding full group {}", group.id);
  TC_AWAIT(_db->putFullGroup(group));
}

tc::cotask<void> GroupStore::put(ExternalGroup const& group)
{
  TINFO("Adding external group {}", group.id);
  TC_AWAIT(_db->putExternalGroup(group));
}

tc::cotask<void> GroupStore::updateLastGroupBlock(
    GroupId const& groupId,
    Crypto::Hash const& lastBlockHash,
    uint64_t lastBlockIndex)
{
  TINFO("Updating group {}, last block is {} {}",
        groupId,
        lastBlockIndex,
        lastBlockHash);
  TC_AWAIT(_db->updateLastGroupBlock(groupId, lastBlockHash, lastBlockIndex));
}

tc::cotask<nonstd::optional<Group>> GroupStore::findFullById(
    GroupId const& groupId) const
{
  TC_RETURN(TC_AWAIT(_db->findFullGroupByGroupId(groupId)));
}

tc::cotask<nonstd::optional<ExternalGroup>> GroupStore::findExternalById(
    GroupId const& groupId) const
{
  TC_RETURN(TC_AWAIT(_db->findExternalGroupByGroupId(groupId)));
}

tc::cotask<nonstd::optional<Group>> GroupStore::findFullByPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& publicEncryptionKey) const
{
  TC_RETURN(TC_AWAIT(
      _db->findFullGroupByGroupPublicEncryptionKey(publicEncryptionKey)));
}

tc::cotask<nonstd::optional<ExternalGroup>>
GroupStore::findExternalByPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& publicEncryptionKey) const
{
  TC_RETURN(TC_AWAIT(
      _db->findExternalGroupByGroupPublicEncryptionKey(publicEncryptionKey)));
}
}
