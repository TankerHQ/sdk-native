
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
  case AppdErrc::TrustchainIsNotTest:
    return "trustchain is not test";
  case AppdErrc::AppNotFound:
    return "trustchain not found";
  case AppdErrc::DeviceNotFound:
    return "device not found";
  case AppdErrc::ProvisionalIdentityNotFound:
    return "provisional identity not found";
  case AppdErrc::ProvisionalIdentityAlreadyAttached:
    return "provisional identity already attached";
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
  case AppdErrc::InvalidToken:
    return "invalid token";
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
  case AppdErrc::TrustchainIsNotTest:
  case AppdErrc::DeviceNotFound:
  case AppdErrc::ProvisionalIdentityNotFound:
  case AppdErrc::UserNotFound:
  case AppdErrc::InvalidToken:
  case AppdErrc::VerificationNeeded: // Handled internally
  case AppdErrc::DeviceRevoked:      // Handled internally
  case AppdErrc::UnknownError:
    return make_error_condition(Errors::Errc::InternalError);
  case AppdErrc::ProvisionalIdentityAlreadyAttached:
    return make_error_condition(Errors::Errc::InvalidArgument);
  case AppdErrc::VerificationCodeNotFound:
  case AppdErrc::InvalidPassphrase:
  case AppdErrc::InvalidVerificationCode:
  case AppdErrc::InvalidDelegationSignature:
    return make_error_condition(Errors::Errc::InvalidVerification);
  case AppdErrc::AppNotFound:
  case AppdErrc::VerificationMethodNotSet:
  case AppdErrc::VerificationKeyNotFound:
    return make_error_condition(Errors::Errc::PreconditionFailed);
  case AppdErrc::TooManyAttempts:
    return make_error_condition(Errors::Errc::TooManyAttempts);
  case AppdErrc::VerificationCodeExpired:
    return make_error_condition(Errors::Errc::ExpiredVerification);
  case AppdErrc::GroupTooBig:
    return make_error_condition(Errors::Errc::GroupTooBig);
  }
  return std::error_condition(c, *this);
}
}
}
