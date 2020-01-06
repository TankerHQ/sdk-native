#include <Tanker/Errors/ServerErrcCategory.hpp>

#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/ServerErrc.hpp>

namespace Tanker
{
namespace Errors
{
namespace detail
{
std::string ServerErrcCategory::message(int c) const
{
  switch (static_cast<ServerErrc>(c))
  {
  case ServerErrc::InternalError:
    return "internal error";
  case ServerErrc::InvalidBody:
    return "invalid body";
  case ServerErrc::InvalidOrigin:
    return "invalid origin";
  case ServerErrc::TrustchainIsNotTest:
    return "trustchain is not test";
  case ServerErrc::TrustchainNotFound:
    return "trustchain not found";
  case ServerErrc::DeviceNotFound:
    return "device not found";
  case ServerErrc::DeviceRevoked:
    return "device revoked";
  case ServerErrc::TooManyAttempts:
    return "too many attempts";
  case ServerErrc::VerificationNeeded:
    return "verification needed";
  case ServerErrc::InvalidPassphrase:
    return "invalid passphrase";
  case ServerErrc::InvalidVerificationCode:
    return "invalid verification code";
  case ServerErrc::VerificationCodeExpired:
    return "verification code expired";
  case ServerErrc::VerificationCodeNotFound:
    return "verification code not found";
  case ServerErrc::VerificationMethodNotSet:
    return "verification method not set";
  case ServerErrc::VerificationKeyNotFound:
    return "verification key not found";
  case ServerErrc::GroupTooBig:
    return "group too big";
  case ServerErrc::InvalidDelegationSignature:
    return "invalid delegation signature";
  case ServerErrc::UnknownError:
    return "unknown server error";
  default:
    return "unknown error";
  }
}

std::error_condition ServerErrcCategory::default_error_condition(int c) const
    noexcept
{
  switch (static_cast<ServerErrc>(c))
  {
  case ServerErrc::InternalError:
  case ServerErrc::InvalidBody:
  case ServerErrc::InvalidOrigin:
  case ServerErrc::TrustchainIsNotTest:
  case ServerErrc::TrustchainNotFound:
  case ServerErrc::DeviceNotFound:
  case ServerErrc::UnknownError:
    return make_error_condition(Errors::Errc::InternalError);
  case ServerErrc::VerificationCodeNotFound:
  case ServerErrc::InvalidPassphrase:
  case ServerErrc::InvalidVerificationCode:
  case ServerErrc::InvalidDelegationSignature:
    return make_error_condition(Errors::Errc::InvalidVerification);
  case ServerErrc::VerificationMethodNotSet:
  case ServerErrc::VerificationKeyNotFound:
    return make_error_condition(Errors::Errc::PreconditionFailed);
  case ServerErrc::TooManyAttempts:
    return make_error_condition(Errors::Errc::TooManyAttempts);
  case ServerErrc::VerificationCodeExpired:
    return make_error_condition(Errors::Errc::ExpiredVerification);
  case ServerErrc::GroupTooBig:
    return make_error_condition(Errors::Errc::GroupTooBig);
  case ServerErrc::DeviceRevoked:
    return make_error_condition(Errors::Errc::DeviceRevoked);
  default:
    return std::error_condition(c, *this);
  }
}
}
}
}
