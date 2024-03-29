#include <Tanker/Groups/Accessor.hpp>

#include <Tanker/Actions/Deduplicate.hpp>
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

#include <range/v3/action/join.hpp>
#include <range/v3/action/stable_sort.hpp>
#include <range/v3/functional/on.hpp>
#include <range/v3/range/conversion.hpp>
#include <range/v3/view/chunk.hpp>
#include <range/v3/view/group_by.hpp>
#include <range/v3/view/map.hpp>
#include <range/v3/view/set_algorithm.hpp>
#include <range/v3/view/transform.hpp>

#include <boost/container/flat_set.hpp>

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

tc::cotask<InternalGroup> Accessor::getInternalGroup(Trustchain::GroupId const& groupId)
{
  auto groupPullResult = TC_AWAIT(getGroups({groupId}));

  if (!groupPullResult.notFound.empty())
    throw formatEx(Errors::Errc::InvalidArgument, "group not found: {:s}", groupId);

  TC_RETURN(boost::variant2::visit(
      overloaded{
          [&](InternalGroup const& group) { return group; },
          [&](ExternalGroup const& group) -> InternalGroup {
            throw formatEx(Errors::Errc::InvalidArgument, "user is not a member of this group {:s}", groupId);
          },
      },
      groupPullResult.found[0]));
}

tc::cotask<Accessor::PublicEncryptionKeyPullResult> Accessor::getPublicEncryptionKeys(
    std::vector<Trustchain::GroupId> const& groupIds)
{
  PublicEncryptionKeyPullResult out;
  boost::container::flat_set<Trustchain::GroupId> found;

  auto entries = TC_AWAIT(_getPublicEncryptionKeyCoalescer.run(
      [&](std::vector<Trustchain::GroupId> const& ids) -> tc::cotask<std::vector<GroupEntry>> {
        TC_RETURN(TC_AWAIT(getPublicEncryptionKeysImpl(ids)));
      },
      groupIds));

  for (auto const& entry : entries)
  {
    found.insert(entry.id);
    out.found.push_back(getPublicEncryptionKey(entry.group));
  }

  for (auto const& groupId : groupIds)
    if (found.find(groupId) == found.end())
      out.notFound.push_back(groupId);

  TC_RETURN(std::move(out));
}

tc::cotask<std::vector<Accessor::GroupEntry>> Accessor::getPublicEncryptionKeysImpl(
    gsl::span<Trustchain::GroupId const> groupIds)
{
  std::vector<GroupEntry> out;
  std::vector<Trustchain::GroupId> notFound;
  for (auto const& groupId : groupIds)
  {
    auto const group = TC_AWAIT(_groupStore->findById(groupId));
    if (group)
      out.push_back({getGroupId(*group), *group});
    else
      notFound.push_back(groupId);
  }

  if (!notFound.empty())
  {
    auto groupPullResult = TC_AWAIT(getGroups(std::move(notFound)));

    for (auto const& group : groupPullResult.found)
      out.push_back({getGroupId(group), group});
  }

  TC_RETURN(std::move(out));
}

tc::cotask<std::optional<Crypto::EncryptionKeyPair>> Accessor::getEncryptionKeyPair(
    Crypto::PublicEncryptionKey const& publicEncryptionKey)
{
  auto const keys = std::vector{publicEncryptionKey};
  auto const keyPairs = TC_AWAIT(_getEncryptionKeyPairCoalescer.run(
      [&](std::vector<Crypto::PublicEncryptionKey> const& publicKeys)
          -> tc::cotask<std::vector<EncryptionKeyPairEntry>> {
        TC_RETURN(TC_AWAIT(getEncryptionKeyPairsImpl(publicKeys)));
      },
      keys));

  if (keyPairs.size() != 1)
    TC_RETURN(std::nullopt);

  TC_RETURN(std::make_optional(keyPairs[0].keyPair));
}

tc::cotask<std::vector<Accessor::EncryptionKeyPairEntry>> Accessor::getEncryptionKeyPairsImpl(
    gsl::span<Crypto::PublicEncryptionKey const> publicEncryptionKeys)
{
  std::vector<EncryptionKeyPairEntry> out;

  for (auto const& publicEncryptionKey : publicEncryptionKeys)
  {
    {
      auto const group = TC_AWAIT(_groupStore->findInternalByPublicEncryptionKey(publicEncryptionKey));
      if (group)
      {
        out.push_back({
            group->encryptionKeyPair.publicKey,
            group->encryptionKeyPair,
        });
        continue;
      }
    }

    auto const entries = TC_AWAIT(_requester->getGroupBlocks(publicEncryptionKey));
    if (entries.empty())
      continue;

    auto const group = TC_AWAIT(GroupUpdater::processGroupEntries(
        *_localUserAccessor, *_userAccessor, *_provisionalUserAccessor, std::nullopt, entries));
    if (!group)
      throw Errors::AssertionError(fmt::format("group {} has no blocks", publicEncryptionKey));

    // add the group to cache
    TC_AWAIT(_groupStore->put(*group));

    if (auto const internalGroup = boost::variant2::get_if<InternalGroup>(&group.value()))
      out.push_back({
          internalGroup->encryptionKeyPair.publicKey,
          internalGroup->encryptionKeyPair,
      });
  }

  TC_RETURN(std::move(out));
}

auto Accessor::partitionGroups(std::vector<Trustchain::GroupAction> entries) -> GroupMap
{
  entries |= ranges::actions::stable_sort(ranges::less{}, Trustchain::getGroupId);
  return entries | ranges::views::group_by(ranges::on(std::equal_to{}, Trustchain::getGroupId)) |
         ranges::views::transform([](auto const& entries) {
           return std::make_pair(Trustchain::getGroupId(entries.front()), entries | ranges::to<std::vector>);
         }) |
         ranges::to<GroupMap>;
}

tc::cotask<std::vector<Trustchain::GroupAction>> Accessor::getGroupEntries(
    gsl::span<Trustchain::GroupId const> groupIds)
{
  std::vector<std::vector<Trustchain::GroupAction>> batchedEntries;

  for (auto const chunk : groupIds | ranges::views::chunk(ChunkSize))
    batchedEntries.push_back(TC_AWAIT(_requester->getGroupBlocks(chunk)));
  TC_RETURN(std::move(batchedEntries) | ranges::actions::join);
}

tc::cotask<std::vector<Group>> Accessor::processGroupEntries(GroupMap const& groups)
{
  std::vector<Group> ret;
  ret.reserve(groups.size());

  for (auto const& [id, entries] : groups)
  {
    auto group = TC_AWAIT(GroupUpdater::processGroupEntries(
        *_localUserAccessor, *_userAccessor, *_provisionalUserAccessor, std::nullopt, entries));
    if (!group)
      throw Errors::AssertionError(fmt::format("group {} has no blocks", id));
    ret.push_back(std::move(*group));
    TC_AWAIT(_groupStore->put(ret.back()));
  }
  TC_RETURN(ret);
}

tc::cotask<Accessor::GroupPullResult> Accessor::getGroups(std::vector<Trustchain::GroupId> groupIds)
{
  groupIds |= Actions::deduplicate;

  auto const groupMap = partitionGroups(TC_AWAIT(getGroupEntries(groupIds)));
  auto const processedGroupIds = groupMap | ranges::views::keys;
  auto const missingIds = ranges::views::set_difference(groupIds, processedGroupIds);

  // ensure that the server did not return more groups than asked
  if (ranges::distance(ranges::views::set_difference(processedGroupIds, groupIds)) != 0)
    throw Errors::AssertionError{"server returned more groups than asked"};

  TC_RETURN((Accessor::GroupPullResult{TC_AWAIT(processGroupEntries(groupMap)), missingIds | ranges::to<std::vector>}));
}
}
