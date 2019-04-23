#include <Tanker/Identity/TargetType.hpp>

namespace Tanker
{
namespace Identity
{
std::string to_string(TargetType t)
{
#define CASE(ARG)       \
  case TargetType::ARG: \
    return #ARG

  switch (t)
  {
    CASE(Email);
  default:
    return "INVALID";
  }
#undef CASE
}
}
}
