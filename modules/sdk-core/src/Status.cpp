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
    CASE(Closed);
    CASE(UserCreation);
    CASE(DeviceCreation);
    CASE(Open);
    CASE(Last);
  default:
    return "INVALID";
  }
#undef CASE
}
}
