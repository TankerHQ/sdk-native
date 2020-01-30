#pragma once

#include <Tanker/ProvisionalUsers/IAccessor.hpp>
#include <Tanker/Types/ProvisionalUserKeys.hpp>

#include <trompeloeil.hpp>

class ProvisionalUsersAccessorMock
  : public trompeloeil::mock_interface<Tanker::ProvisionalUsers::IAccessor>
{
  IMPLEMENT_MOCK2(pullEncryptionKeys);
  IMPLEMENT_MOCK2(findEncryptionKeysFromCache);
  IMPLEMENT_MOCK0(refreshKeys);
};