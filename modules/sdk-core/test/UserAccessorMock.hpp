#pragma once

#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/UserAccessor.hpp>

#include <trompeloeil.hpp>

class UserAccessorMock : public Tanker::IUserAccessor
{
public:
  MAKE_MOCK1(pull,
             tc::cotask<Tanker::IUserAccessor::PullResult>(
                 gsl::span<Tanker::Trustchain::UserId const>),
             override);
  MAKE_MOCK1(pullProvisional,
             tc::cotask<std::vector<Tanker::PublicProvisionalUser>>(
                 gsl::span<Tanker::Identity::PublicProvisionalIdentity const>),
             override);
};
