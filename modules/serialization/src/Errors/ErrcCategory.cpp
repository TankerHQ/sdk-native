#include <Tanker/Serialization/Errors/ErrcCategory.hpp>

#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Serialization/Errors/Errc.hpp>

namespace Tanker
{
namespace Serialization
{
namespace detail
{
std::string ErrcCategory::message(int c) const
{
  switch (static_cast<Errc>(c))
  {
  case Errc::TrailingInput:
    return "trailing input";
  case Errc::TruncatedInput:
    return "truncated input";
  default:
    return "unknown error";
  }
}

std::error_condition ErrcCategory::default_error_condition(int c) const noexcept
{
  switch (static_cast<Errc>(c))
  {
  case Errc::TrailingInput:
  case Errc::TruncatedInput:
    return make_error_condition(Errors::Errc::InvalidArgument);
  default:
    return std::error_condition(c, *this);
  }
}
}
}
}
