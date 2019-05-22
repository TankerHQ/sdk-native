#pragma once

#include <string>
#include <system_error>

namespace Tanker
{
namespace Errors
{
namespace detail
{
class ErrcCategory : public std::error_category
{
public:
  char const* name() const noexcept override final
  {
    return "Tanker";
  }

  std::string message(int c) const override final;
};
}

extern inline detail::ErrcCategory const& ErrcCategory()
{
  static detail::ErrcCategory c;
  return c;
}
}
}
