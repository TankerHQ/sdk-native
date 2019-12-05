#include <Tanker/Groups/Accessor.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Groups/IRequester.hpp>
#include <Tanker/Groups/Store.hpp>
#include <Tanker/Groups/Updater.hpp>
#include <Tanker/ITrustchainPuller.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>

#include <boost/container/flat_map.hpp>

TLOG_CATEGORY("GroupAccessor");

using Tanker::Trustchain::GroupId;

namespace Tanker::Groups
{
Accessor::Accessor(Trustchain::UserId const& userId,
                   Groups::IRequester* requester,
                   ITrustchainPuller* trustchainPuller,
                   Users::ContactStore const* contactStore,
                   Store* groupStore,
                   Users::UserKeyStore const* userKeyStore,
                   ProvisionalUsers::IAccessor* provisionalUserAccessor)
  : _myUserId(userId),
    _requester(requester),
    _trustchainPuller(trustchainPuller),
    _contactStore(contactStore),
    _groupStore(groupStore),
    _userKeyStore(userKeyStore),
    _provisionalUserAccessor(provisionalUserAccessor)
{
}

tc::cotask<Accessor::InternalGroupPullResult> Accessor::getInternalGroups(
    std::vector<Trustchain::GroupId> const& groupIds)
{
  // This function is only called when updating group members, and in that
  // case we need the last block of the group. Since there is no way to know
  // if we are up to date, just pull the group again
  auto groupPullResult = TC_AWAIT(getGroups(groupIds));

  InternalGroupPullResult out;
  out.notFound = std::move(groupPullResult.notFound);
  for (auto const& group : groupPullResult.found)
  {
    if (auto const internalGroup =
            boost::variant2::get_if<InternalGroup>(&group))
      out.found.push_back(*internalGroup);
    else if (auto const externalGroup =
                 boost::variant2::get_if<ExternalGroup>(&group))
      out.notFound.push_back(externalGroup->id);
  }

  TC_RETURN(out);
}

tc::cotask<Accessor::PublicEncryptionKeyPullResult>
Accessor::getPublicEncryptionKeys(
    std::vector<Trustchain::GroupId> const& groupIds)
{
  PublicEncryptionKeyPullResult out;
  for (auto const& groupId : groupIds)
  {
    auto const group = TC_AWAIT(_groupStore->findById(groupId));
    if (group)
      out.found.push_back(getPublicEncryptionKey(*group));
    else
      out.notFound.push_back(groupId);
  }

  if (!out.notFound.empty())
  {
    auto groupPullResult = TC_AWAIT(getGroups(out.notFound));

    out.notFound = std::move(groupPullResult.notFound);
    for (auto const& group : groupPullResult.found)
      out.found.push_back(getPublicEncryptionKey(group));
  }

  TC_RETURN(out);
}

tc::cotask<std::optional<Crypto::EncryptionKeyPair>>
Accessor::getEncryptionKeyPair(
    Crypto::PublicEncryptionKey const& publicEncryptionKey)
{
  {
    auto const group = TC_AWAIT(
        _groupStore->findInternalByPublicEncryptionKey(publicEncryptionKey));
    if (group)
      TC_RETURN(group->encryptionKeyPair);
  }

  auto const entries =
      TC_AWAIT(_requester->getGroupBlocks(publicEncryptionKey));

  if (entries.empty())
    TC_RETURN(std::nullopt);

  auto const group =
      TC_AWAIT(GroupUpdater::processGroupEntries(_myUserId,
                                                 *_trustchainPuller,
                                                 *_contactStore,
                                                 *_userKeyStore,
                                                 *_provisionalUserAccessor,
                                                 std::nullopt,
                                                 entries));
  if (!group)
    throw Errors::AssertionError(
        fmt::format("group {} has no blocks", publicEncryptionKey));

  // add the group to cache
  TC_AWAIT(_groupStore->put(*group));

  if (auto const internalGroup =
          boost::variant2::get_if<InternalGroup>(&*group))
    TC_RETURN(internalGroup->encryptionKeyPair);
  else
    TC_RETURN(std::nullopt);
}

tc::cotask<void> Accessor::fetch(gsl::span<GroupId const> groupIds)
{
  TC_AWAIT(_trustchainPuller->scheduleCatchUp(
      {}, std::vector<GroupId>{groupIds.begin(), groupIds.end()}));
}

namespace
{
using GroupMap =
    boost::container::flat_map<Trustchain::GroupId,
                               std::vector<Trustchain::ServerEntry>>;

GroupMap partitionGroups(std::vector<Trustchain::ServerEntry> const& entries)
{
  GroupMap out;
  for (auto const& entry : entries)
  {
    if (auto const userGroupCreation =
            entry.action().get_if<Trustchain::Actions::UserGroupCreation>())
      out[GroupId{userGroupCreation->publicSignatureKey()}].push_back(entry);
    else if (auto const userGroupAddition =
                 entry.action()
                     .get_if<Trustchain::Actions::UserGroupAddition>())
      out[userGroupAddition->groupId()].push_back(entry);
    else
      TERROR("Expected group blocks but got {}", entry.action().nature());
  }
  return out;
}
}

tc::cotask<Accessor::GroupPullResult> Accessor::getGroups(
    std::vector<Trustchain::GroupId> const& groupIds)
{
  auto const entries = TC_AWAIT(_requester->getGroupBlocks(groupIds));
  auto const groupMap = partitionGroups(entries);

  GroupPullResult out;
  for (auto const& groupId : groupIds)
  {
    auto const groupEntriesIt = groupMap.find(groupId);
    if (groupEntriesIt == groupMap.end())
      out.notFound.push_back(groupId);
    else
    {
      auto const group =
          TC_AWAIT(GroupUpdater::processGroupEntries(_myUserId,
                                                     *_trustchainPuller,
                                                     *_contactStore,
                                                     *_userKeyStore,
                                                     *_provisionalUserAccessor,
                                                     std::nullopt,
                                                     groupEntriesIt->second));
      if (!group)
        throw Errors::AssertionError(
            fmt::format("group {} has no blocks", groupId));
      out.found.push_back(*group);
    }
  }

  // add all the groups to cache
  for (auto const& group : out.found)
    TC_AWAIT(_groupStore->put(group));

  TC_RETURN(out);
}
}
