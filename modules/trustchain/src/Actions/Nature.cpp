#include <Tanker/Trustchain/Actions/Nature.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
std::string to_string(Nature n)
{
#define NATURE_CASE(ARG) \
  case Nature::ARG:      \
    return #ARG

  switch (n)
  {
    NATURE_CASE(TrustchainCreation);
    NATURE_CASE(DeviceCreation1);
    NATURE_CASE(KeyPublishToDevice);
    NATURE_CASE(DeviceRevocation1);
    NATURE_CASE(DeviceCreation2);
    NATURE_CASE(DeviceCreation3);
    NATURE_CASE(KeyPublishToUser);
    NATURE_CASE(DeviceRevocation2);
    NATURE_CASE(UserGroupCreation1);
    NATURE_CASE(KeyPublishToUserGroup);
    NATURE_CASE(UserGroupAddition1);
    NATURE_CASE(KeyPublishToProvisionalUser);
    NATURE_CASE(ProvisionalIdentityClaim);
    NATURE_CASE(UserGroupCreation2);
    NATURE_CASE(UserGroupAddition2);
    NATURE_CASE(UserGroupCreation3);
    NATURE_CASE(UserGroupAddition3);
    NATURE_CASE(SessionCertificate);
    NATURE_CASE(UserGroupRemoval);
  }
  return "INVALID";
}
}
}
}
