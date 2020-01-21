#pragma once

#include <Tanker/Identity/PublicProvisionalIdentity.hpp>
#include <Tanker/ProvisionalUsers/PublicUser.hpp>
#include <Tanker/Trustchain/Context.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/IRequester.hpp>
#include <Tanker/Users/IUserAccessor.hpp>

#include <gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <boost/container/flat_map.hpp>

#include <optional>
#include <vector>

namespace Tanker::Users
{
class ContactStore;
using UsersMap = boost::container::flat_map<Trustchain::UserId, Users::User>;
using DevicesMap = boost::container::flat_map<Trustchain::DeviceId, Device>;

class UserAccessor : public IUserAccessor
{
public:
  UserAccessor(Trustchain::Context trustchainCtx,
               Users::IRequester* requester,
               ContactStore const* contactStore);

  UserAccessor() = delete;
  UserAccessor(UserAccessor const&) = delete;
  UserAccessor(UserAccessor&&) = delete;
  UserAccessor& operator=(UserAccessor const&) = delete;
  UserAccessor& operator=(UserAccessor&&) = delete;

  tc::cotask<PullResult> pull(gsl::span<Trustchain::UserId const> userIds);
  tc::cotask<BasicPullResult<Device, Trustchain::DeviceId>> pull(
      gsl::span<Trustchain::DeviceId const> deviceIds);
  tc::cotask<std::vector<ProvisionalUsers::PublicUser>> pullProvisional(
      gsl::span<Identity::PublicProvisionalIdentity const>
          appProvisionalIdentities);

private:
  auto fetch(gsl::span<Trustchain::UserId const> userIds)
      -> tc::cotask<UsersMap>;
  auto fetch(gsl::span<Trustchain::DeviceId const> deviceIds)
      -> tc::cotask<DevicesMap>;

private:
  Trustchain::Context _context;
  Users::IRequester* _requester;
  ContactStore const* _contactStore;
};
}
