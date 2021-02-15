#pragma once

#include <Tanker/BasicPullResult.hpp>
#include <Tanker/Identity/PublicProvisionalIdentity.hpp>
#include <Tanker/ProvisionalUsers/PublicUser.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/User.hpp>

#include <tconcurrent/coroutine.hpp>

#include <gsl/gsl-lite.hpp>

namespace Tanker::Users
{
class IUserAccessor
{
public:
  using UserPullResult = BasicPullResult<User, Trustchain::UserId>;

  virtual tc::cotask<UserPullResult> pull(
      std::vector<Trustchain::UserId> userIds) = 0;
  virtual tc::cotask<BasicPullResult<Device, Trustchain::DeviceId>> pull(
      std::vector<Trustchain::DeviceId> deviceIds) = 0;
  virtual tc::cotask<std::vector<ProvisionalUsers::PublicUser>> pullProvisional(
      std::vector<Identity::PublicProvisionalIdentity>
          appProvisionalIdentities) = 0;
};
}
