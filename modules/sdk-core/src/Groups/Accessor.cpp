#include <Tanker/Groups/Accessor.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Groups/IRequester.hpp>
#include <Tanker/Groups/Store.hpp>
#include <Tanker/Groups/Updater.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>
#include <Tanker/Types/Overloaded.hpp>
#include <Tanker/Users/ILocalUserAccessor.hpp>

#include <boost/container/flat_map.hpp>

TLOG_CATEGORY("GroupAccessor");

static constexpr auto ChunkSize = 100;

using Tanker::Trustchain::GroupId;

namespace Tanker::Groups
{
Accessor::Accessor(Groups::IRequester* requester,
                   Users::IUserAccessor* accessor,
                   Store* groupStore,
                   Users::ILocalUserAccessor* localUserAccessor,
                   ProvisionalUsers::IAccessor* provisionalUserAccessor)
  : _requester(requester),
    _userAccessor(accessor),
    _groupStore(groupStore),
    _localUserAccessor(localUserAccessor),
    _provisionalUserAccessor(provisionalUserAccessor)
{
}

tc::cotask<InternalGroup> Accessor::getInternalGroup(
    Trustchain::GroupId const& groupId)
{
  auto groupPullResult = TC_AWAIT(getGroups({groupId}));

  if (!groupPullResult.notFound.empty())
    throw formatEx(
        Errors::Errc::InvalidArgument, "group not found: {:s}", groupId);

  TC_RETURN(boost::variant2::visit(
      overloaded{
          [&](InternalGroup const& group) { return group; },
          [&](ExternalGroup const& group) -> InternalGroup {
            throw formatEx(Errors::Errc::InvalidArgument,
                           "user is not part of group {:s}",
                           groupId);
          },
      },
      groupPullResult.found[0]));
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
      TC_AWAIT(GroupUpdater::processGroupEntries(*_localUserAccessor,
                                                 *_userAccessor,
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

namespace
{
using GroupMap =
    boost::container::flat_map<Trustchain::GroupId,
                               std::vector<Trustchain::GroupAction>>;

GroupMap partitionGroups(std::vector<Trustchain::GroupAction> const& entries)
{
  GroupMap out;
  for (auto const& action : entries)
  {
    boost::variant2::visit(
        overloaded{
            [&](const Trustchain::Actions::UserGroupCreation&
                    userGroupCreation) {
              out[GroupId{userGroupCreation.publicSignatureKey()}].push_back(
                  action);
            },
            [&](const Trustchain::Actions::UserGroupAddition&
                    userGroupAddition) {
              out[userGroupAddition.groupId()].push_back(action);
            },
        },
        action);
  }
  return out;
}
}

tc::cotask<Accessor::GroupPullResult> Accessor::getGroups(
    std::vector<Trustchain::GroupId> const& groupIds)
{
  std::vector<Trustchain::GroupAction> entries;
  entries.reserve(groupIds.size());
  for (unsigned int i = 0; i < groupIds.size(); i += ChunkSize)
  {
    auto const count = std::min<unsigned int>(ChunkSize, groupIds.size() - i);
    auto response = TC_AWAIT(
        _requester->getGroupBlocks(gsl::make_span(groupIds).subspan(i, count)));
    entries.insert(entries.end(),
                   std::make_move_iterator(response.begin()),
                   std::make_move_iterator(response.end()));
  }
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
          TC_AWAIT(GroupUpdater::processGroupEntries(*_localUserAccessor,
                                                     *_userAccessor,
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
