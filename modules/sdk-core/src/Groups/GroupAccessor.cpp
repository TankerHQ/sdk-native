#include <Tanker/Groups/GroupAccessor.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Groups/GroupStore.hpp>
#include <Tanker/Groups/GroupUpdater.hpp>
#include <Tanker/Groups/Requests.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>
#include <Tanker/TrustchainPuller.hpp>

#include <mockaron/mockaron.hpp>

#include <boost/container/flat_map.hpp>

TLOG_CATEGORY("GroupAccessor");

using Tanker::Trustchain::GroupId;

namespace Tanker
{
GroupAccessor::GroupAccessor(
    Trustchain::UserId const& userId,
    Client* client,
    TrustchainPuller* trustchainPuller,
    ContactStore const* contactStore,
    GroupStore* groupStore,
    UserKeyStore const* userKeyStore,
    ProvisionalUserKeysStore const* provisionalUserKeysStore)
  : _myUserId(userId),
    _client(client),
    _trustchainPuller(trustchainPuller),
    _contactStore(contactStore),
    _groupStore(groupStore),
    _userKeyStore(userKeyStore),
    _provisionalUserKeysStore(provisionalUserKeysStore)
{
}

tc::cotask<GroupAccessor::InternalGroupPullResult>
GroupAccessor::getInternalGroups(
    std::vector<Trustchain::GroupId> const& groupIds)
{
  MOCKARON_HOOK_CUSTOM(
      tc::cotask<InternalGroupPullResult>(std::vector<GroupId> const&),
      InternalGroupPullResult,
      GroupAccessor,
      getInternalGroups,
      TC_RETURN,
      MOCKARON_ADD_COMMA(groupIds));

  InternalGroupPullResult out;
  for (auto const& groupId : groupIds)
  {
    auto const group = TC_AWAIT(_groupStore->findById(groupId));
    if (group)
      if (auto const internalGroup =
              boost::variant2::get_if<InternalGroup>(&*group))
      {
        out.found.push_back(*internalGroup);
        continue;
      }
    out.notFound.push_back(groupId);
  }

  auto const groupPullResult = TC_AWAIT(getGroups(out.notFound));

  out.notFound = groupPullResult.notFound;
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

tc::cotask<GroupAccessor::PublicEncryptionKeyPullResult>
GroupAccessor::getPublicEncryptionKeys(
    std::vector<Trustchain::GroupId> const& groupIds)
{
  MOCKARON_HOOK_CUSTOM(
      tc::cotask<PublicEncryptionKeyPullResult>(std::vector<GroupId> const&),
      PublicEncryptionKeyPullResult,
      GroupAccessor,
      getPublicEncryptionKeys,
      TC_RETURN,
      MOCKARON_ADD_COMMA(groupIds));

  PublicEncryptionKeyPullResult out;
  for (auto const& groupId : groupIds)
  {
    auto const group = TC_AWAIT(_groupStore->findById(groupId));
    if (group)
      out.found.push_back(getPublicEncryptionKey(*group));
    else
      out.notFound.push_back(groupId);
  }

  auto const groupPullResult = TC_AWAIT(getGroups(out.notFound));

  out.notFound = groupPullResult.notFound;
  for (auto const& group : groupPullResult.found)
    out.found.push_back(getPublicEncryptionKey(group));

  TC_RETURN(out);
}

tc::cotask<nonstd::optional<Crypto::EncryptionKeyPair>>
GroupAccessor::getEncryptionKeyPair(
    Crypto::PublicEncryptionKey const& publicEncryptionKey)
{
  MOCKARON_HOOK_CUSTOM(tc::cotask<nonstd::optional<Crypto::EncryptionKeyPair>>(
                           Crypto::PublicEncryptionKey const&),
                       nonstd::optional<Crypto::EncryptionKeyPair>,
                       GroupAccessor,
                       getEncryptionKeyPair,
                       TC_RETURN,
                       MOCKARON_ADD_COMMA(publicEncryptionKey));

  {
    auto const group = TC_AWAIT(
        _groupStore->findInternalByPublicEncryptionKey(publicEncryptionKey));
    if (group)
      TC_RETURN(group->encryptionKeyPair);
  }

  auto const entries =
      TC_AWAIT(Groups::Requests::getGroupBlocks(_client, publicEncryptionKey));

  if (entries.empty())
    TC_RETURN(nonstd::nullopt);

  auto const group =
      TC_AWAIT(GroupUpdater::processGroupEntries(_myUserId,
                                                 *_trustchainPuller,
                                                 *_contactStore,
                                                 *_userKeyStore,
                                                 *_provisionalUserKeysStore,
                                                 nonstd::nullopt,
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
    TC_RETURN(nonstd::nullopt);
}

tc::cotask<void> GroupAccessor::fetch(gsl::span<GroupId const> groupIds)
{
  TC_AWAIT(_trustchainPuller->scheduleCatchUp(
      {}, std::vector<GroupId>{groupIds.begin(), groupIds.end()}));
}

auto GroupAccessor::getInternalGroup(
    Crypto::PublicEncryptionKey const& publicGroupKey)
    -> tc::cotask<nonstd::optional<InternalGroup>>
{
  // We don't need to fetch full groups because
  // we know they are up to date.
  auto const maybeGroup =
      TC_AWAIT(_groupStore->findInternalByPublicEncryptionKey(publicGroupKey));
  if (maybeGroup)
    TC_RETURN(maybeGroup);
  TC_AWAIT(_trustchainPuller->scheduleCatchUp({}, {}));
  TC_RETURN(
      TC_AWAIT(_groupStore->findInternalByPublicEncryptionKey(publicGroupKey)));
}

auto GroupAccessor::pull(gsl::span<GroupId const> groupIds)
    -> tc::cotask<PullResult>
{
  MOCKARON_HOOK_CUSTOM(tc::cotask<PullResult>(gsl::span<GroupId const>),
                       PullResult,
                       GroupAccessor,
                       pull,
                       TC_RETURN,
                       MOCKARON_ADD_COMMA(groupIds));

  std::vector<GroupId> groupsToFetch;
  PullResult ret;
  ret.found.reserve(groupIds.size());

  for (auto const& id : groupIds)
  {
    // We don't need to fetch full groups because
    // we know they are up to date.
    auto const maybeGroup = TC_AWAIT(_groupStore->findInternalById(id));
    if (maybeGroup)
      ret.found.emplace_back(maybeGroup.value());
    else
      groupsToFetch.emplace_back(id);
  }

  if (!groupsToFetch.empty())
  {
    TC_AWAIT(fetch(groupsToFetch));

    auto first = std::begin(groupsToFetch);
    auto const itend = std::end(groupsToFetch);
    for (auto it = first; it != itend; ++it)
    {
      auto const opt =
          extractExternalGroup(TC_AWAIT(_groupStore->findById(*it)));
      if (opt)
        ret.found.emplace_back(opt.value());
      else
        *first++ = std::move(*it);
    }
    groupsToFetch.erase(first, itend);
    ret.notFound = std::move(groupsToFetch);
  }

  TC_RETURN(ret);
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

tc::cotask<GroupAccessor::GroupPullResult> GroupAccessor::getGroups(
    std::vector<Trustchain::GroupId> const& groupIds)
{
  auto const entries =
      TC_AWAIT(Groups::Requests::getGroupBlocks(_client, groupIds));
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
                                                     *_provisionalUserKeysStore,
                                                     nonstd::nullopt,
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
