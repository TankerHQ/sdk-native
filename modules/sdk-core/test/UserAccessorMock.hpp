#pragma once

#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/UserAccessor.hpp>

#include <mockaron/mockaron.hpp>

#include <trompeloeil.hpp>

class UserAccessorMock : public mockaron::mock_impl
{
public:
  UserAccessorMock()
  {
    MOCKARON_DECLARE_IMPL_CUSTOM(
        tc::cotask<Tanker::UserAccessor::PullResult>(
            gsl::span<Tanker::Trustchain::UserId const>),
        Tanker::UserAccessor::PullResult,
        Tanker::UserAccessor,
        pull);
    MOCKARON_DECLARE_IMPL_CUSTOM(
        tc::cotask<std::vector<Tanker::PublicProvisionalUser>>(
            gsl::span<Tanker::Identity::PublicProvisionalIdentity const>),
        std::vector<Tanker::PublicProvisionalUser>,
        Tanker::UserAccessor,
        pullProvisional);
  }

  MAKE_MOCK1(pull,
             Tanker::UserAccessor::PullResult(
                 gsl::span<Tanker::Trustchain::UserId const>));
  MAKE_MOCK1(pullProvisional,
             std::vector<Tanker::PublicProvisionalUser>(
                 gsl::span<Tanker::Identity::PublicProvisionalIdentity const>));
};
