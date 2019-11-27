#pragma once

#include <Tanker/BasicPullResult.hpp>
#include <Tanker/Identity/PublicProvisionalIdentity.hpp>
#include <Tanker/PublicProvisionalUser.hpp>
#include <Tanker/User.hpp>

#include <tconcurrent/coroutine.hpp>

#include <gsl-lite.hpp>

namespace Tanker
{
class IUserAccessor
{
public:
  using PullResult = BasicPullResult<User>;

  virtual tc::cotask<PullResult> pull(
      gsl::span<Trustchain::UserId const> userIds) = 0;
  virtual tc::cotask<std::vector<PublicProvisionalUser>> pullProvisional(
      gsl::span<Identity::PublicProvisionalIdentity const>
          appProvisionalIdentities) = 0;
};
}
