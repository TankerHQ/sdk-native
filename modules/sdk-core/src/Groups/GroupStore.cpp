#include <Tanker/Groups/GroupStore.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Log/Log.hpp>

#include <optional.hpp>
#include <tconcurrent/coroutine.hpp>

TLOG_CATEGORY(GroupStore);

using Tanker::Trustchain::GroupId;

namespace Tanker
{
GroupStore::GroupStore(DataStore::ADatabase* dbConn) : _db(dbConn)
{
}

tc::cotask<void> GroupStore::put(Group const& group)
{
  TC_AWAIT(boost::variant2::visit(
      [this](auto const& g) -> tc::cotask<void> { TC_AWAIT(put(g)); }, group));
}

tc::cotask<void> GroupStore::put(InternalGroup const& group)
{
  TINFO("Adding internal group {}", group.id);
  TC_AWAIT(_db->putInternalGroup(group));
}

tc::cotask<void> GroupStore::put(ExternalGroup const& group)
{
  TINFO("Adding external group {}", group.id);
  TC_AWAIT(_db->putExternalGroup(group));
}

tc::cotask<void> GroupStore::putGroupProvisionalEncryptionKeys(
    Trustchain::GroupId const& groupId,
    std::vector<GroupProvisionalUser> const& provisionalUsers)
{
  if (provisionalUsers.empty())
    TC_RETURN();

  TINFO("Adding group provisional encryption keys {}", groupId);
  TC_AWAIT(_db->putGroupProvisionalEncryptionKeys(groupId, provisionalUsers));
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

tc::cotask<nonstd::optional<InternalGroup>> GroupStore::findInternalById(
    GroupId const& groupId) const
{
  TC_RETURN(TC_AWAIT(_db->findInternalGroupByGroupId(groupId)));
}

tc::cotask<nonstd::optional<ExternalGroup>> GroupStore::findExternalById(
    GroupId const& groupId) const
{
  TC_RETURN(TC_AWAIT(_db->findExternalGroupByGroupId(groupId)));
}

tc::cotask<nonstd::optional<InternalGroup>>
GroupStore::findInternalByPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& publicEncryptionKey) const
{
  TC_RETURN(TC_AWAIT(
      _db->findInternalGroupByGroupPublicEncryptionKey(publicEncryptionKey)));
}

tc::cotask<nonstd::optional<ExternalGroup>>
GroupStore::findExternalByPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& publicEncryptionKey) const
{
  TC_RETURN(TC_AWAIT(
      _db->findExternalGroupByGroupPublicEncryptionKey(publicEncryptionKey)));
}

tc::cotask<std::vector<ExternalGroup>>
GroupStore::findExternalGroupsByProvisionalUser(
    Crypto::PublicSignatureKey const& appPublicSignatureKey,
    Crypto::PublicSignatureKey const& tankerPublicSignatureKey) const
{
  TC_RETURN(TC_AWAIT(_db->findExternalGroupsByProvisionalUser(
      appPublicSignatureKey, tankerPublicSignatureKey)));
}
}
