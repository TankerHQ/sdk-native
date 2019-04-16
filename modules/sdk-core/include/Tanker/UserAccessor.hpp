#pragma once

#include <Tanker/BasicPullResult.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/User.hpp>

#include <gsl-lite.hpp>
#include <optional.hpp>
#include <tconcurrent/coroutine.hpp>

#include <vector>

namespace Tanker
{
class TrustchainPuller;
class ContactStore;

class UserAccessor
{
public:
  using PullResult = BasicPullResult<User>;

  UserAccessor(Trustchain::UserId const& selfUserId,
               TrustchainPuller* trustchainPuller,
               ContactStore const* contactStore);

  UserAccessor() = delete;
  UserAccessor(UserAccessor const&) = delete;
  UserAccessor(UserAccessor&&) = delete;
  UserAccessor& operator=(UserAccessor const&) = delete;
  UserAccessor& operator=(UserAccessor&&) = delete;

  tc::cotask<PullResult> pull(gsl::span<Trustchain::UserId const> userIds);

private:
  tc::cotask<void> fetch(gsl::span<Trustchain::UserId const> userIds);

private:
  Trustchain::UserId _selfUserId;

  TrustchainPuller* _trustchainPuller;
  ContactStore const* _contactStore;
};
}
