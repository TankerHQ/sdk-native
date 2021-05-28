#include <Tanker/Groups/Accessor.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>
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

  // The key could have changed due to a new GroupUpdate block, so always fetch
  auto groupPullResult = TC_AWAIT(getGroups(groupIds));

  out.notFound = std::move(groupPullResult.notFound);
  for (auto const& group : groupPullResult.found)
    out.found.push_back(getPublicEncryptionKey(group));

  TC_RETURN(out);
}

tc::cotask<std::optional<Crypto::EncryptionKeyPair>>
Accessor::getEncryptionKeyPair(
    Crypto::PublicEncryptionKey const& publicEncryptionKey)
{
  {
    auto const groupKey = TC_AWAIT(
        _groupStore->findKeyByPublicEncryptionKey(publicEncryptionKey));
    if (groupKey)
      TC_RETURN(groupKey);
  }

  auto const entries =
      TC_AWAIT(_requester->getGroupBlocks(publicEncryptionKey));
  if (entries.empty())
    TC_RETURN(std::nullopt);

  auto const [group, groupKeys] =
      TC_AWAIT(GroupUpdater::processGroupEntries(*_localUserAccessor,
                                                 *_userAccessor,
                                                 *_provisionalUserAccessor,
                                                 std::nullopt,
                                                 entries));
  if (!group)
    throw Errors::AssertionError(
        fmt::format("group {} has no blocks", publicEncryptionKey));

  // add the group keys to cache
  auto const groupId = getGroupId(*group);
  auto const result =
      std::find_if(groupKeys.begin(), groupKeys.end(), [&](auto const& key) {
        return key.publicKey == publicEncryptionKey;
      });
  TC_AWAIT(_groupStore->putKeys(groupId, groupKeys));
  TC_RETURN(result != groupKeys.end() ? std::make_optional(*result) :
                                        std::nullopt);
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
            [&](const Trustchain::Actions::UserGroupUpdate& userGroupUpdate) {
              out[userGroupUpdate.groupId()].push_back(action);
            }},
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
      auto const [group, groupKeys] =
          TC_AWAIT(GroupUpdater::processGroupEntries(*_localUserAccessor,
                                                     *_userAccessor,
                                                     *_provisionalUserAccessor,
                                                     std::nullopt,
                                                     groupEntriesIt->second));
      if (!group)
        throw Errors::AssertionError(
            fmt::format("group {} has no blocks", groupId));
      out.found.push_back(*group);

      // add the group and group keys to cache
      TC_AWAIT(_groupStore->putKeys(groupId, groupKeys));
    }
  }

  TC_RETURN(out);
}
}
