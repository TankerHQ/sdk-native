#include <Tanker/Groups/GroupAccessor.hpp>

#include <Tanker/Groups/GroupStore.hpp>
#include <Tanker/TrustchainPuller.hpp>

#include <mockaron/mockaron.hpp>

using Tanker::Trustchain::GroupId;

namespace Tanker
{
GroupAccessor::GroupAccessor(TrustchainPuller* trustchainPuller,
                             GroupStore const* groupStore)
  : _trustchainPuller(trustchainPuller), _groupStore(groupStore)
{
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
}
