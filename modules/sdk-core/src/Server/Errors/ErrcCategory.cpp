#include <Tanker/Server/Errors/ErrcCategory.hpp>

#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Server/Errors/Errc.hpp>

namespace Tanker
{
namespace Server
{
namespace detail
{
std::string ErrcCategory::message(int c) const
{
  switch (static_cast<Errc>(c))
  {
  case Errc::InternalError:
    return "internal error";
  case Errc::InvalidBody:
    return "invalid body";
  case Errc::InvalidOrigin:
    return "invalid origin";
  case Errc::TrustchainIsNotTest:
    return "trustchain is not test";
  case Errc::TrustchainNotFound:
    return "trustchain not found";
  case Errc::DeviceNotFound:
    return "device not found";
  case Errc::DeviceRevoked:
    return "device revoked";
  case Errc::TooManyAttempts:
    return "too many attempts";
  case Errc::VerificationNeeded:
    return "verification needed";
  case Errc::InvalidPassphrase:
    return "invalid passphrase";
  case Errc::InvalidVerificationCode:
    return "invalid verification code";
  case Errc::VerificationCodeExpired:
    return "verification code expired";
  case Errc::VerificationCodeNotFound:
    return "verification code not found";
  case Errc::VerificationMethodNotSet:
    return "verification method not set";
  case Errc::VerificationKeyNotFound:
    return "verification key not found";
  case Errc::GroupTooBig:
    return "group too big";
  case Errc::InvalidDelegationSignature:
    return "invalid delegation signature";
  case Errc::UnknownError:
    return "unknown server error";
  default:
    return "unknown error";
  }
}

std::error_condition ErrcCategory::default_error_condition(int c) const noexcept
{
  switch (static_cast<Errc>(c))
  {
  case Errc::InternalError:
  case Errc::InvalidBody:
  case Errc::InvalidOrigin:
  case Errc::TrustchainIsNotTest:
  case Errc::TrustchainNotFound:
  case Errc::DeviceRevoked:
  case Errc::DeviceNotFound:
  case Errc::UnknownError:
    return make_error_condition(Errors::Errc::InternalError);
  case Errc::VerificationCodeNotFound:
  case Errc::InvalidPassphrase:
  case Errc::InvalidVerificationCode:
  case Errc::InvalidDelegationSignature:
    return make_error_condition(Errors::Errc::InvalidVerification);
  case Errc::VerificationMethodNotSet:
  case Errc::VerificationKeyNotFound:
    return make_error_condition(Errors::Errc::PreconditionFailed);
  case Errc::TooManyAttempts:
    return make_error_condition(Errors::Errc::TooManyAttempts);
  case Errc::VerificationCodeExpired:
    return make_error_condition(Errors::Errc::ExpiredVerification);
  case Errc::GroupTooBig:
    return make_error_condition(Errors::Errc::GroupTooBig);
  default:
    return std::error_condition(c, *this);
  }
}
}
}
}
