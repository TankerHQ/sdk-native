#pragma once

#include <string>
#include <system_error>

namespace Tanker
{
namespace Crypto
{
namespace detail
{
class ErrcCategory : public std::error_category
{
public:
  char const* name() const noexcept override final
  {
    return "Crypto";
  }

  std::string message(int c) const override final;
  std::error_condition default_error_condition(int c) const
      noexcept override final;
};
}

extern inline detail::ErrcCategory const& ErrcCategory()
{
  static detail::ErrcCategory c;
  return c;
}
}
}
