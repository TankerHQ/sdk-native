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
#include <boost/container/flat_set.hpp>

TLOG_CATEGORY("GroupAccessor");

static constexpr auto ChunkSize = 100;

using Tanker::Trustchain::GroupId;
using namespace Tanker::Trustchain::Actions;

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
  auto groupPullResult =
      TC_AWAIT(getGroups(groupIds, Groups::IRequester::IsLight::Yes));

  InternalGroupPullResult out;
  out.notFound = std::move(groupPullResult.notFound);
  for (auto const& group : groupPullResult.found)
  {
    if (auto const internalGroup =
            boost::variant2::get_if<InternalGroup>(&group.group))
      out.found.push_back(*internalGroup);
    else if (auto const externalGroup =
                 boost::variant2::get_if<ExternalGroup>(&group.group))
      out.notFound.push_back(externalGroup->id);
  }

  TC_RETURN(out);
}

tc::cotask<Accessor::InternalGroupAndMembersPullResult>
Accessor::getInternalGroupsAndMembers(
    std::vector<Trustchain::GroupId> const& groupIds)
{
  auto groupPullResult =
      TC_AWAIT(getGroups(groupIds, Groups::IRequester::IsLight::No));

  InternalGroupAndMembersPullResult out;
  out.notFound = std::move(groupPullResult.notFound);
  for (auto&& group : groupPullResult.found)
  {
    if (auto const internalGroup =
            boost::variant2::get_if<InternalGroup>(&group.group))
      out.found.push_back({*internalGroup,
                           std::move(group.members),
                           std::move(group.provisionalMembers)});
    else if (auto const externalGroup =
                 boost::variant2::get_if<ExternalGroup>(&group.group))
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
  auto groupPullResult =
      TC_AWAIT(getGroups(groupIds, Groups::IRequester::IsLight::Yes));

  out.notFound = std::move(groupPullResult.notFound);
  for (auto const& group : groupPullResult.found)
    out.found.push_back(getPublicEncryptionKey(group.group));

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

tc::cotask<Accessor::GroupAndMembersPullResult> Accessor::getGroups(
    std::vector<Trustchain::GroupId> const& groupIds,
    IRequester::IsLight isLight,
    bool fillMembers)
{
  std::vector<Trustchain::GroupAction> entries;
  entries.reserve(groupIds.size());
  for (unsigned int i = 0; i < groupIds.size(); i += ChunkSize)
  {
    auto const count = std::min<unsigned int>(ChunkSize, groupIds.size() - i);
    auto response = TC_AWAIT(_requester->getGroupBlocks(
        gsl::make_span(groupIds).subspan(i, count), isLight));
    entries.insert(entries.end(),
                   std::make_move_iterator(response.begin()),
                   std::make_move_iterator(response.end()));
  }
  auto const groupMap = partitionGroups(entries);

  GroupAndMembersPullResult out;
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

      // add the group and group keys to cache
      TC_AWAIT(_groupStore->putKeys(groupId, groupKeys));

      if (fillMembers)
        out.found.push_back(getGroupMembers(*group, groupEntriesIt->second));
      else
        out.found.push_back(GroupAndMembers<Group>{*group, {}, {}});
    }
  }

  TC_RETURN(out);
}

static void updateGroupMembersList(
    UserGroupCreation const& base_action,
    boost::container::flat_set<UserGroupMember2>& members,
    boost::container::flat_set<UserGroupProvisionalMember3>& provisionalMembers)
{
  base_action.visit(
      overloaded{[&](const UserGroupCreation::v1& userGroupCreation) {
                   throw Errors::Exception(
                       make_error_code(Errors::Errc::UnsupportedGroupVersion),
                       "group block V1 unsupported");
                 },
                 [&](const UserGroupCreation::v2& userGroupCreation) {
                   if (!userGroupCreation.provisionalMembers().empty())
                     throw Errors::Exception(
                         make_error_code(Errors::Errc::UnsupportedGroupVersion),
                         "group block V2 provisional users unsupported");
                   members.insert(userGroupCreation.members().begin(),
                                  userGroupCreation.members().end());
                 },
                 [&](const UserGroupCreation::v3& userGroupCreation) {
                   members.insert(userGroupCreation.members().begin(),
                                  userGroupCreation.members().end());
                   provisionalMembers.insert(
                       userGroupCreation.provisionalMembers().begin(),
                       userGroupCreation.provisionalMembers().end());
                 }});
}

static void updateGroupMembersList(
    UserGroupAddition const& base_action,
    boost::container::flat_set<UserGroupMember2>& members,
    boost::container::flat_set<UserGroupProvisionalMember3>& provisionalMembers)
{
  base_action.visit(overloaded{
      [&](const UserGroupAddition::v1& userGroupAddition) {
        throw Errors::Exception(
            make_error_code(Errors::Errc::UnsupportedGroupVersion),
            "group block V1 unsupported");
      },
      [&](const UserGroupAddition::v2& userGroupAddition) {
        if (!userGroupAddition.provisionalMembers().empty())
          throw Errors::Exception(
              make_error_code(Errors::Errc::UnsupportedGroupVersion),
              "group block V2 provisional users unsupported");
        auto const& newMembers = userGroupAddition.members();
        members.insert(newMembers.begin(), newMembers.end());
      },
      [&](const UserGroupAddition::v3& userGroupAddition) {
        auto const& newMembers = userGroupAddition.members();
        members.insert(newMembers.begin(), newMembers.end());
        auto const& newProvMembers = userGroupAddition.provisionalMembers();
        provisionalMembers.insert(newProvMembers.begin(), newProvMembers.end());
      }});
}

static void updateGroupMembersList(
    UserGroupUpdate const& base_action,
    boost::container::flat_set<UserGroupMember2>& members,
    boost::container::flat_set<UserGroupProvisionalMember3>& provisionalMembers)
{
  if (auto const action = base_action.get_if<UserGroupUpdate::v1>())
  {
    members.clear();
    members.insert(action->members().begin(), action->members().end());
    provisionalMembers.clear();
    provisionalMembers.insert(action->provisionalMembers().begin(),
                              action->provisionalMembers().end());
  }
  else
  {
    throw Errors::AssertionError(
        fmt::format("unreachable code, all versions should be handled"));
  }
}

GroupAndMembers<Group> Accessor::getGroupMembers(
    Group group, std::vector<Trustchain::GroupAction> const& entries)
{
  boost::container::flat_set<UserGroupMember2> members;
  boost::container::flat_set<UserGroupProvisionalMember3> provisionalMembers;

  for (auto rit = entries.rbegin(); rit != entries.rend(); ++rit)
  {
    auto isGroupUpdate = boost::variant2::visit(
        overloaded{
            [&](const Trustchain::Actions::UserGroupCreation&
                    userGroupCreation) {
              updateGroupMembersList(
                  userGroupCreation, members, provisionalMembers);
              return false;
            },
            [&](const Trustchain::Actions::UserGroupAddition&
                    userGroupAddition) {
              updateGroupMembersList(
                  userGroupAddition, members, provisionalMembers);
              return false;
            },
            [&](const Trustchain::Actions::UserGroupUpdate& userGroupUpdate) {
              updateGroupMembersList(
                  userGroupUpdate, members, provisionalMembers);
              return true;
            }},
        *rit);
    if (isGroupUpdate)
    {
      break; // GroupUpdate is not a diff, it resets the member list
    }
  }
  std::vector<UserGroupMember2> membersVec;
  membersVec.insert(membersVec.end(), members.begin(), members.end());
  std::vector<UserGroupProvisionalMember3> provisionalMembersVec;
  provisionalMembersVec.insert(provisionalMembersVec.end(),
                               provisionalMembers.begin(),
                               provisionalMembers.end());

  return GroupAndMembers<Group>{
      group,
      membersVec,
      provisionalMembersVec,
  };
}
}
