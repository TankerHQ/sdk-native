
#include <Tanker/Errors/AppdErrcCategory.hpp>

#include <Tanker/Errors/AppdErrc.hpp>
#include <Tanker/Errors/Errc.hpp>

namespace Tanker::Errors
{
namespace detail
{
std::string AppdErrcCategory::message(int c) const
{
  switch (static_cast<AppdErrc>(c))
  {
  case AppdErrc::InternalError:
    return "internal error";
  case AppdErrc::InvalidBody:
    return "invalid body";
  case AppdErrc::InvalidOrigin:
    return "invalid origin";
  case AppdErrc::TrustchainIsNotTest:
    return "trustchain is not test";
  case AppdErrc::AppNotFound:
    return "trustchain not found";
  case AppdErrc::DeviceNotFound:
    return "device not found";
  case AppdErrc::DeviceRevoked:
    return "device revoked";
  case AppdErrc::TooManyAttempts:
    return "too many attempts";
  case AppdErrc::VerificationNeeded:
    return "verification needed";
  case AppdErrc::InvalidPassphrase:
    return "invalid passphrase";
  case AppdErrc::InvalidVerificationCode:
    return "invalid verification code";
  case AppdErrc::VerificationCodeExpired:
    return "verification code expired";
  case AppdErrc::VerificationCodeNotFound:
    return "verification code not found";
  case AppdErrc::VerificationMethodNotSet:
    return "verification method not set";
  case AppdErrc::VerificationKeyNotFound:
    return "verification key not found";
  case AppdErrc::GroupTooBig:
    return "group too big";
  case AppdErrc::InvalidDelegationSignature:
    return "invalid delegation signature";
  case AppdErrc::UnknownError:
    return "unknown server error";
  case AppdErrc::UserNotFound:
    return "user not found";
  }
  return "unknown error";
}

std::error_condition AppdErrcCategory::default_error_condition(int c) const
    noexcept
{
  switch (static_cast<AppdErrc>(c))
  {
  case AppdErrc::InternalError:
  case AppdErrc::InvalidBody:
  case AppdErrc::InvalidOrigin:
  case AppdErrc::TrustchainIsNotTest:
  case AppdErrc::AppNotFound:
  case AppdErrc::DeviceNotFound:
  case AppdErrc::UserNotFound:
  case AppdErrc::UnknownError:
    return make_error_condition(Errors::Errc::InternalError);
  case AppdErrc::VerificationCodeNotFound:
  case AppdErrc::InvalidPassphrase:
  case AppdErrc::InvalidVerificationCode:
  case AppdErrc::InvalidDelegationSignature:
    return make_error_condition(Errors::Errc::InvalidVerification);
  case AppdErrc::VerificationMethodNotSet:
  case AppdErrc::VerificationKeyNotFound:
  case AppdErrc::InvalidToken:
    return make_error_condition(Errors::Errc::PreconditionFailed);
  case AppdErrc::TooManyAttempts:
    return make_error_condition(Errors::Errc::TooManyAttempts);
  case AppdErrc::VerificationCodeExpired:
    return make_error_condition(Errors::Errc::ExpiredVerification);
  case AppdErrc::GroupTooBig:
    return make_error_condition(Errors::Errc::GroupTooBig);
  case AppdErrc::DeviceRevoked:
    return make_error_condition(Errors::Errc::DeviceRevoked);
  case AppdErrc::VerificationNeeded: // Handled internally
    break;
  }
  return std::error_condition(c, *this);
}
}
}
