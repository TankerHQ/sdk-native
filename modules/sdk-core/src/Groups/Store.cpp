#include <Tanker/Groups/Store.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/Database.hpp>
#include <Tanker/Log/Log.hpp>

#include <optional>
#include <tconcurrent/coroutine.hpp>

TLOG_CATEGORY(GroupStore);

using Tanker::Trustchain::GroupId;

namespace Tanker::Groups
{
Store::Store(DataStore::Database* dbConn) : _db(dbConn)
{
}

tc::cotask<void> Store::put(Group const& group)
{
  TC_AWAIT(boost::variant2::visit(
      [this](auto const& g) -> tc::cotask<void> { TC_AWAIT(put(g)); }, group));
}

tc::cotask<void> Store::put(InternalGroup const& group)
{
  TINFO("Adding internal group {}", group.id);
  TC_AWAIT(_db->putInternalGroup(group));
}

tc::cotask<void> Store::put(ExternalGroup const& group)
{
  TINFO("Adding external group {}", group.id);
  TC_AWAIT(_db->putExternalGroup(group));
}

tc::cotask<std::optional<Group>> Store::findById(GroupId const& groupId) const
{
  TC_RETURN(TC_AWAIT(_db->findGroupByGroupId(groupId)));
}

tc::cotask<std::optional<InternalGroup>>
Store::findInternalByPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& publicEncryptionKey) const
{
  auto const group =
      TC_AWAIT(_db->findGroupByGroupPublicEncryptionKey(publicEncryptionKey));
  if (!group)
    TC_RETURN(std::nullopt);
  else if (auto const internalGroup =
               boost::variant2::get_if<InternalGroup>(&*group))
    TC_RETURN(*internalGroup);
  else
    TC_RETURN(std::nullopt);
}

tc::cotask<std::optional<Group>> Store::findByPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& publicEncryptionKey) const
{
  TC_RETURN(
      TC_AWAIT(_db->findGroupByGroupPublicEncryptionKey(publicEncryptionKey)));
}
}
