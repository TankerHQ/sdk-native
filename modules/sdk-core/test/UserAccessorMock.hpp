#pragma once

#include <Tanker/Types/UserId.hpp>

#include <mockaron/mockaron.hpp>

#include <trompeloeil/trompeloeil.hpp>

class UserAccessorMock : public mockaron::mock_impl
{
public:
  UserAccessorMock()
  {
    MOCKARON_DECLARE_IMPL_CUSTOM(tc::cotask<Tanker::UserAccessor::PullResult>(
                                     gsl::span<Tanker::UserId const>),
                                 Tanker::UserAccessor::PullResult,
                                 Tanker::UserAccessor,
                                 pull);
  }

  MAKE_MOCK1(pull,
             Tanker::UserAccessor::PullResult(gsl::span<Tanker::UserId const>));
};
