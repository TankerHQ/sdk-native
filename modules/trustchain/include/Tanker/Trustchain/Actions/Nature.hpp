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
  DeviceCreation1 = 2,
  KeyPublishToDevice = 3,
  DeviceRevocation1 = 4,
  DeviceCreation2 = 6,
  DeviceCreation3 = 7,
  KeyPublishToUser = 8,
  DeviceRevocation2 = 9,
  UserGroupCreation1 = 10,
  KeyPublishToUserGroup = 11,
  UserGroupAddition1 = 12,
  KeyPublishToProvisionalUser = 13,
  ProvisionalIdentityClaim = 14,
  UserGroupCreation2 = 15,
  UserGroupAddition2 = 16,
  UserGroupCreation3 = 17,
  UserGroupAddition3 = 18,
  SessionCertificate = 19,
};

std::string to_string(Nature);
}
}
}
