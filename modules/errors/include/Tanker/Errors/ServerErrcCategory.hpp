#pragma once

#include <string>
#include <system_error>

namespace Tanker
{
namespace Errors
{
namespace detail
{
class ServerErrcCategory : public std::error_category
{
public:
  char const* name() const noexcept override final
  {
    return "Server";
  }

  std::string message(int c) const override final;
  std::error_condition default_error_condition(int c) const
      noexcept override final;
};
}

extern inline detail::ServerErrcCategory const& ServerErrcCategory()
{
  static detail::ServerErrcCategory c;
  return c;
}
}
}
