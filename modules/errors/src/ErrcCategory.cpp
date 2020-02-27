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
  case Errc::DecryptionFailed:
    return "decryption failed";
  case Errc::GroupTooBig:
    return "group too big";
  case Errc::InvalidVerification:
    return "invalid verification";
  case Errc::TooManyAttempts:
    return "too many attempts";
  case Errc::ExpiredVerification:
    return "expired verification";
  case Errc::IOError:
    return "input/output error";
  case Errc::DeviceRevoked:
    return "device was revoked";
  case Errc::Conflict:
    return "conflict";
  case Errc::Last:
    break;
  }
  return "unknown error";
}
}
}
}
