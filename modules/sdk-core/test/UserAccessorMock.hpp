#pragma once

#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/IUserAccessor.hpp>

#include <trompeloeil.hpp>

class UserAccessorMock : public Tanker::Users::IUserAccessor
{
public:
  MAKE_MOCK1(pull,
             tc::cotask<Tanker::Users::IUserAccessor::PullResult>(
                 gsl::span<Tanker::Trustchain::UserId const>),
             override);
  MAKE_MOCK1(pullProvisional,
             tc::cotask<std::vector<Tanker::PublicProvisionalUser>>(
                 gsl::span<Tanker::Identity::PublicProvisionalIdentity const>),
             override);
};
