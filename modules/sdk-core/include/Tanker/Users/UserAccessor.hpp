#pragma once

#include <Tanker/Identity/PublicProvisionalIdentity.hpp>
#include <Tanker/ProvisionalUsers/PublicUser.hpp>
#include <Tanker/Trustchain/Context.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/IRequester.hpp>
#include <Tanker/Users/IUserAccessor.hpp>

#include <gsl/gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <boost/container/flat_map.hpp>

#include <optional>
#include <vector>

namespace Tanker::Users
{
using UsersMap = boost::container::flat_map<Trustchain::UserId, Users::User>;
using DevicesMap = boost::container::flat_map<Trustchain::DeviceId, Device>;

class UserAccessor : public IUserAccessor
{
public:
  UserAccessor(Trustchain::Context trustchainCtx, Users::IRequester* requester);

  UserAccessor() = delete;
  UserAccessor(UserAccessor const&) = delete;
  UserAccessor(UserAccessor&&) = delete;
  UserAccessor& operator=(UserAccessor const&) = delete;
  UserAccessor& operator=(UserAccessor&&) = delete;

  tc::cotask<UserPullResult> pull(
      std::vector<Trustchain::UserId> userIds) override;
  tc::cotask<DevicePullResult> pull(
      std::vector<Trustchain::DeviceId> deviceIds) override;
  tc::cotask<std::vector<ProvisionalUsers::PublicUser>> pullProvisional(
      std::vector<Identity::PublicProvisionalIdentity> appProvisionalIdentities)
      override;

private:
  auto fetch(gsl::span<Trustchain::UserId const> userIds)
      -> tc::cotask<UsersMap>;
  auto fetch(gsl::span<Trustchain::DeviceId const> deviceIds)
      -> tc::cotask<DevicesMap>;
  template <typename Result, typename Id>
  auto fetchImpl(gsl::span<Id const> ids) -> tc::cotask<Result>;

  template <typename Result, typename Id>
  auto pullImpl(std::vector<Id> ids) -> tc::cotask<Result>;

private:
  Trustchain::Context _context;
  Users::IRequester* _requester;
};
}
