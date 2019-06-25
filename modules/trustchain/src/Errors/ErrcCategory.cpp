#include <Tanker/Trustchain/Errors/ErrcCategory.hpp>

#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Trustchain/Errors/Errc.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace detail
{
std::string ErrcCategory::message(int c) const
{
  switch (static_cast<Errc>(c))
  {
  case Errc::InvalidBlockVersion:
    return "invalid block version";
  case Errc::InvalidBlockNature:
    return "invalid block nature";
  case Errc::InvalidLastResetField:
    return "invalid last reset field";
  default:
    return "unknown error";
  }
}

std::error_condition ErrcCategory::default_error_condition(int c) const noexcept
{
  switch (static_cast<Errc>(c))
  {
    case Errc::InvalidBlockVersion:
    case Errc::InvalidBlockNature:
    case Errc::InvalidLastResetField:
      return make_error_condition(Errors::Errc::InternalError);
    default:
      return std::error_condition(c, *this);
  }
}
}
}
}
