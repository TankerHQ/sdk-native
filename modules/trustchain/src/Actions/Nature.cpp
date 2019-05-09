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
    NATURE_CASE(DeviceCreation);
    NATURE_CASE(KeyPublishToDevice);
    NATURE_CASE(DeviceRevocation);
    NATURE_CASE(DeviceCreation2);
    NATURE_CASE(DeviceCreation3);
    NATURE_CASE(KeyPublishToUser);
    NATURE_CASE(DeviceRevocation2);
    NATURE_CASE(UserGroupCreation);
    NATURE_CASE(KeyPublishToUserGroup);
    NATURE_CASE(UserGroupAddition);
    NATURE_CASE(KeyPublishToProvisionalUser);
    NATURE_CASE(ProvisionalIdentityClaim);
    NATURE_CASE(UserGroupCreation2);
    NATURE_CASE(UserGroupAddition2);
  }
  return "INVALID";
}
}
}
}
