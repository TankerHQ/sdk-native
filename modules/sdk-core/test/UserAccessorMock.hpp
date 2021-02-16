#pragma once

#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/Device.hpp>
#include <Tanker/Users/IUserAccessor.hpp>

#include <trompeloeil.hpp>

class UserAccessorMock : public Tanker::Users::IUserAccessor
{
public:
  MAKE_MOCK1(pull,
             tc::cotask<Tanker::Users::IUserAccessor::PullResult>(
                 std::vector<Tanker::Trustchain::UserId>),
             override);
  MAKE_MOCK1(pull,
             (tc::cotask<Tanker::BasicPullResult<Tanker::Users::Device,
                                                 Tanker::Trustchain::DeviceId>>(
                 std::vector<Tanker::Trustchain::DeviceId> deviceIds)),
             override);
  MAKE_MOCK1(pullProvisional,
             tc::cotask<std::vector<Tanker::ProvisionalUsers::PublicUser>>(
                 std::vector<Tanker::Identity::PublicProvisionalIdentity>),
             override);
};
