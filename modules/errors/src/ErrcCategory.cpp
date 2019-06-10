#include <Tanker/Errors/ErrcCategory.hpp>

#include <Tanker/Errors/Errc.hpp>

namespace Tanker
{
namespace Errors
{
namespace detail
{
std::string ErrcCategory::message(int c) const
{
  switch (static_cast<Errc>(c))
  {
  case Errc::InvalidArgument:
    return "invalid argument";
  case Errc::InternalError:
    return "internal error";
  case Errc::NetworkError:
    return "network error";
  case Errc::PreconditionFailed:
    return "precondition failed";
  case Errc::OperationCanceled:
    return "operation canceled";
  case Errc::OperationForbidden:
    return "operation forbidden";
  case Errc::DecryptionFailed:
    return "decryption failed";
  case Errc::InvalidGroupSize:
    return "invalid group size";
  case Errc::NotFound:
    return "not found";
  case Errc::AlreadyExists:
    return "already exists";
  case Errc::InvalidCredentials:
    return "invalid credentials";
  case Errc::TooManyAttempts:
    return "too many attempts";
  case Errc::Expired:
    return "expired";
  case Errc::DeviceRevoked:
    return "device revoked";
  default:
    return "unknown error";
  }
}
}
}
}
