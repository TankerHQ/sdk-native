#include <Tanker/Nature.hpp>

#include <string>

namespace Tanker
{
std::string to_string(Nature n)
{
#define CASE(ARG)   \
  case Nature::ARG: \
    return #ARG

  switch (n)
  {
    CASE(TrustchainCreation);
    CASE(DeviceCreation);
    CASE(KeyPublishToDevice);
    CASE(DeviceRevocation);
    CASE(DeviceCreation2);
    CASE(DeviceCreation3);
    CASE(KeyPublishToUser);
    CASE(DeviceRevocation2);
    CASE(UserGroupCreation);
    CASE(KeyPublishToUserGroup);
    CASE(UserGroupAddition);
  }
#undef CASE
  return "INVALID";
}
}
