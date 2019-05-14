#include <Tanker/Status.hpp>

namespace Tanker
{
std::string to_string(Status s)
{
#define CASE(ARG)   \
  case Status::ARG: \
    return #ARG

  switch (s)
  {
    CASE(Stopped);
    CASE(Ready);
    CASE(IdentityRegistrationNeeded);
    CASE(IdentityVerificationNeeded);
  default:
    return "INVALID";
  }
#undef CASE
}
}
