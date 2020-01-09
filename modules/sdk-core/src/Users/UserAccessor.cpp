#include <Tanker/Users/UserAccessor.hpp>

#include <Tanker/Entry.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/ITrustchainPuller.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Users/ContactStore.hpp>

#include <tconcurrent/coroutine.hpp>

using Tanker::Trustchain::UserId;

using namespace Tanker::Errors;

namespace Tanker::Users
{
UserAccessor::UserAccessor(UserId const& selfUserId,
                           Users::IRequester* requester,
                           ITrustchainPuller* trustchainPuller,
                           ContactStore const* contactStore)
  : _selfUserId(selfUserId),
    _requester(requester),
    _trustchainPuller(trustchainPuller),
    _contactStore(contactStore)
{
}

auto UserAccessor::pull(gsl::span<UserId const> userIds)
    -> tc::cotask<PullResult>
{
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
  if (appProvisionalIdentities.empty())
    TC_RETURN(std::vector<PublicProvisionalUser>{});

  std::vector<Email> provisionalUserEmails;
  for (auto const& appProvisionalIdentity : appProvisionalIdentities)
  {
    if (appProvisionalIdentity.target != Identity::TargetType::Email)
    {
      throw AssertionError(
          fmt::format("unsupported target type: {}",
                      static_cast<int>(appProvisionalIdentity.target)));
    }
    provisionalUserEmails.push_back(Email{appProvisionalIdentity.value});
  }

  auto const tankerProvisionalIdentities = TC_AWAIT(
      _requester->getPublicProvisionalIdentities(provisionalUserEmails));

  if (appProvisionalIdentities.size() != tankerProvisionalIdentities.size())
  {
    throw formatEx(
        Errc::InternalError,
        "getPublicProvisionalIdentities returned a list of different size");
  }

  std::vector<PublicProvisionalUser> provisionalUsers;
  provisionalUsers.reserve(appProvisionalIdentities.size());
  std::transform(appProvisionalIdentities.begin(),
                 appProvisionalIdentities.end(),
                 tankerProvisionalIdentities.begin(),
                 std::back_inserter(provisionalUsers),
                 [](auto const& appProvisionalIdentity,
                    auto const& tankerProvisionalIdentity) {
                   auto const& [sigKey, encKey] = tankerProvisionalIdentity;
                   return PublicProvisionalUser{
                       appProvisionalIdentity.appSignaturePublicKey,
                       appProvisionalIdentity.appEncryptionPublicKey,
                       sigKey,
                       encKey,
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
