#include <Tanker/UserAccessor.hpp>

#include <Tanker/ContactStore.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/TrustchainPuller.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/UserNotFound.hpp>

#include <mockaron/mockaron.hpp>
#include <tconcurrent/coroutine.hpp>

using Tanker::Trustchain::UserId;

namespace Tanker
{
UserAccessor::UserAccessor(UserId const& selfUserId,
                           Client* client,
                           TrustchainPuller* trustchainPuller,
                           ContactStore const* contactStore)
  : _selfUserId(selfUserId),
    _client(client),
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

tc::cotask<std::vector<PublicProvisionalUser>> UserAccessor::pullProvisional(
    gsl::span<Identity::PublicProvisionalIdentity const>
        appProvisionalIdentities)
{
  MOCKARON_HOOK_CUSTOM(
      tc::cotask<std::vector<PublicProvisionalUser>>(
          gsl::span<Identity::PublicProvisionalIdentity const>),
      std::vector<PublicProvisionalUser>,
      UserAccessor,
      pullProvisional,
      TC_RETURN,
      MOCKARON_ADD_COMMA(appProvisionalIdentities));

  if (appProvisionalIdentities.empty())
    TC_RETURN(std::vector<PublicProvisionalUser>{});

  std::vector<Email> provisionalUserEmails;
  for (auto const& appProvisionalIdentity : appProvisionalIdentities)
  {
    if (appProvisionalIdentity.target != Identity::TargetType::Email)
      throw Error::formatEx("unsupported target type: {}",
                            static_cast<int>(appProvisionalIdentity.target));
    provisionalUserEmails.push_back(Email{appProvisionalIdentity.value});
  }

  auto const tankerProvisionalIdentities =
      TC_AWAIT(_client->getPublicProvisionalIdentities(provisionalUserEmails));

  if (appProvisionalIdentities.size() != tankerProvisionalIdentities.size())
    throw Error::InternalError(
        "getPublicProvisionalIdentities returned a list of different size");

  std::vector<PublicProvisionalUser> provisionalUsers;
  provisionalUsers.reserve(appProvisionalIdentities.size());
  std::transform(appProvisionalIdentities.begin(),
                 appProvisionalIdentities.end(),
                 tankerProvisionalIdentities.begin(),
                 std::back_inserter(provisionalUsers),
                 [](auto const& appProvisionalIdentity,
                    auto const& tankerProvisionalIdentity) {
                   return PublicProvisionalUser{
                       appProvisionalIdentity.appSignaturePublicKey,
                       appProvisionalIdentity.appEncryptionPublicKey,
                       tankerProvisionalIdentity.first,
                       tankerProvisionalIdentity.second,
                   };
                 });

  TC_RETURN(provisionalUsers);
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
