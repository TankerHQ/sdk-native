#pragma once

#include <Tanker/BasicPullResult.hpp>
#include <Tanker/Identity/PublicProvisionalIdentity.hpp>
#include <Tanker/ProvisionalUsers/PublicUser.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/User.hpp>

#include <tconcurrent/coroutine.hpp>

#include <gsl-lite.hpp>

namespace Tanker::Users
{
class IUserAccessor
{
public:
  using PullResult = BasicPullResult<User, Trustchain::UserId>;

  virtual tc::cotask<PullResult> pull(
      gsl::span<Trustchain::UserId const> userIds) = 0;
  virtual tc::cotask<std::vector<ProvisionalUsers::PublicUser>> pullProvisional(
      gsl::span<Identity::PublicProvisionalIdentity const>
          appProvisionalIdentities) = 0;
};
}
