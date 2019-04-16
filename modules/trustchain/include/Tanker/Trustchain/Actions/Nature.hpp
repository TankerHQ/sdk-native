#pragma once

#include <string>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
enum class Nature
{
  TrustchainCreation = 1,
  DeviceCreation = 2,
  KeyPublishToDevice = 3,
  DeviceRevocation = 4,
  DeviceCreation2 = 6,
  DeviceCreation3 = 7,
  KeyPublishToUser = 8,
  DeviceRevocation2 = 9,
  UserGroupCreation = 10,
  KeyPublishToUserGroup = 11,
  UserGroupAddition = 12,

  Last = UserGroupAddition,
};

std::string to_string(Nature);
}
}
}
