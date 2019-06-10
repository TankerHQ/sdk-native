#include <Tanker/Verif/Errors/ErrcCategory.hpp>

#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Verif/Errors/Errc.hpp>

namespace Tanker
{
namespace Verif
{
namespace detail
{
std::string ErrcCategory::message(int c) const
{
  switch (static_cast<Errc>(c))
  {
  case Errc::InvalidSignature:
    return "invalid signature";
  case Errc::InvalidAuthor:
    return "invalid author";
  case Errc::InvalidHash:
    return "invalid hash";
  case Errc::InvalidUserKey:
    return "invalidUserKey";
  case Errc::InvalidLastReset:
    return "invalid last reset";
  case Errc::InvalidUserId:
    return "invalid user id";
  case Errc::InvalidDelegationSignature:
    return "invalid delegation signature";
  case Errc::InvalidUser:
    return "invalid user";
  case Errc::InvalidEncryptionKey:
    return "invalid encryption key";
  case Errc::InvalidGroup:
    return "invalid group";
  case Errc::InvalidUserKeys:
    return "invalid user keys";
  case Errc::InvalidTargetDevice:
    return "invalid target device";
  default:
    return "unknown error";
  }
}

std::error_condition ErrcCategory::default_error_condition(int c) const noexcept
{
  switch (static_cast<Errc>(c))
  {
  case Errc::InvalidSignature:
  case Errc::InvalidAuthor:
  case Errc::InvalidHash:
  case Errc::InvalidUserKey:
  case Errc::InvalidLastReset:
  case Errc::InvalidUserId:
  case Errc::InvalidDelegationSignature:
  case Errc::InvalidEncryptionKey:
  case Errc::InvalidGroup:
  case Errc::InvalidUserKeys:
  case Errc::InvalidTargetDevice:
    return make_error_condition(Errors::Errc::InternalError);
  default:
    return std::error_condition(c, *this);
  }
}
}
}
}
