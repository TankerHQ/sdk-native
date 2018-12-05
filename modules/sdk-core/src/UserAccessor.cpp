#include <Tanker/UserAccessor.hpp>

#include <Tanker/ContactStore.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/TrustchainPuller.hpp>
#include <Tanker/UserNotFound.hpp>

#include <mockaron/mockaron.hpp>
#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
UserAccessor::UserAccessor(UserId const& selfUserId,
                           TrustchainPuller* trustchainPuller,
                           ContactStore const* contactStore)
  : _selfUserId(selfUserId),
    _trustchainPuller(trustchainPuller),
    _contactStore(contactStore)
{
}

auto UserAccessor::pull(gsl::span<UserId const> userIds)
    -> tc::cotask<PullResult>
{
  MOCKARON_HOOK_CUSTOM(tc::cotask<PullResult>(gsl::span<UserId const>),
                       PullResult,
                       UserAccessor,
                       pull,
                       TC_RETURN,
                       MOCKARON_ADD_COMMA(userIds));

  TC_AWAIT(fetch(userIds));

  PullResult ret;
  ret.found.reserve(userIds.size());

  for (auto const& userId : userIds)
  {
    auto optUser = TC_AWAIT(_contactStore->findUser(userId));
    if (optUser)
      ret.found.push_back(std::move(*optUser));
    else
      ret.notFound.push_back(userId);
  }

  TC_RETURN(ret);
}

tc::cotask<void> UserAccessor::fetch(gsl::span<UserId const> userIds)
{
  std::vector<UserId> usersWithoutMe;

  usersWithoutMe.reserve(userIds.size());
  std::remove_copy(userIds.begin(),
                   userIds.end(),
                   std::back_inserter(usersWithoutMe),
                   _selfUserId);

  if (!usersWithoutMe.empty())
    TC_AWAIT(_trustchainPuller->scheduleCatchUp(usersWithoutMe));
}
}
