#include <Helpers/Email.hpp>

namespace Tanker
{
auto makeEmail(std::string_view name, std::string_view domain) -> Email
{
  static auto inc = 0u;
  return Email{fmt::format("{:s}-{:d}@{:s}", name, ++inc, domain)};
}
}
