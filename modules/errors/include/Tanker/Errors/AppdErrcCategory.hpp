#pragma once

#include <string>
#include <system_error>

namespace Tanker::Errors
{
namespace detail
{
class AppdErrcCategory : public std::error_category
{
public:
  char const* name() const noexcept override final
  {
    return "Appd";
  }

  std::string message(int c) const override final;
  std::error_condition default_error_condition(
      int c) const noexcept override final;
};
}

extern inline detail::AppdErrcCategory const& AppdErrcCategory()
{
  static detail::AppdErrcCategory c;
  return c;
}
}