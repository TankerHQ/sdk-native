#pragma once

#include <Tanker/BasicPullResult.hpp>
#include <Tanker/Client.hpp>
#include <Tanker/IUserAccessor.hpp>
#include <Tanker/Identity/PublicProvisionalIdentity.hpp>
#include <Tanker/PublicProvisionalUser.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/User.hpp>

#include <gsl-lite.hpp>
#include <optional>
#include <tconcurrent/coroutine.hpp>

#include <vector>

namespace Tanker
{
class TrustchainPuller;
class ContactStore;

class UserAccessor : public IUserAccessor
{
public:
  UserAccessor(Trustchain::UserId const& selfUserId,
               Client* client,
               TrustchainPuller* trustchainPuller,
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

  Client* _client;
  TrustchainPuller* _trustchainPuller;
  ContactStore const* _contactStore;
};
}
