#include <Helpers/PhoneNumber.hpp>

namespace Tanker
{
PhoneNumber makePhoneNumber(std::string_view prefix)
{
  static auto inc = 0u;
  return PhoneNumber{fmt::format("{:s}{:0>4d}", prefix, ++inc)};
}
}
