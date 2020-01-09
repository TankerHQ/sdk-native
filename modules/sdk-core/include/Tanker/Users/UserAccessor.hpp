#pragma once

#include <Tanker/Identity/PublicProvisionalIdentity.hpp>
#include <Tanker/PublicProvisionalUser.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/IRequester.hpp>
#include <Tanker/Users/IUserAccessor.hpp>

#include <gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <optional>
#include <vector>

namespace Tanker
{
class ITrustchainPuller;
}

namespace Tanker::Users
{
class ContactStore;

class UserAccessor : public IUserAccessor
{
public:
  UserAccessor(Trustchain::UserId const& selfUserId,
               Users::IRequester* requester,
               ITrustchainPuller* trustchainPuller,
               ContactStore const* contactStore);

  UserAccessor() = delete;
  UserAccessor(UserAccessor const&) = delete;
  UserAccessor(UserAccessor&&) = delete;
  UserAccessor& operator=(UserAccessor const&) = delete;
  UserAccessor& operator=(UserAccessor&&) = delete;

  tc::cotask<PullResult> pull(gsl::span<Trustchain::UserId const> userIds);
  tc::cotask<std::vector<PublicProvisionalUser>> pullProvisional(
      gsl::span<Identity::PublicProvisionalIdentity const>
          appProvisionalIdentities);

private:
  tc::cotask<void> fetch(gsl::span<Trustchain::UserId const> userIds);

private:
  Trustchain::UserId _selfUserId;

  Users::IRequester* _requester;
  ITrustchainPuller* _trustchainPuller;
  ContactStore const* _contactStore;
};
}
