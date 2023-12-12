#pragma once

#include <Tanker/Users/LocalUserAccessor.hpp>

#include <trompeloeil.hpp>

namespace Tanker
{
class LocalUserAccessorMock : public trompeloeil::mock_interface<Users::ILocalUserAccessor>
{
public:
  IMPLEMENT_CONST_MOCK0(get);
  IMPLEMENT_MOCK0(pull);
  IMPLEMENT_MOCK1(pullUserKeyPair);
};
}
