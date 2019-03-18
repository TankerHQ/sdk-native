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
    CASE(Open);
  default:
    return "INVALID";
  }
#undef CASE
}
}
