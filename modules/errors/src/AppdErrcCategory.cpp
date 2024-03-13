
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
  case AppdErrc::TooManyAttempts:
    return "too many attempts";
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
  case AppdErrc::Blocked:
    return "blocked";
  case AppdErrc::UpgradeRequired:
    return "upgrade required";
  case AppdErrc::BadRequest:
    return "bad request";
  case AppdErrc::InvalidChallengeSignature:
    return "invalid challenge signature";
  case AppdErrc::InvalidChallengePublicKey:
    return "invalid challenge public key";
  case AppdErrc::NotAUserGroupMember:
    return "not a user group member";
  case AppdErrc::EmptyUserGroup:
    return "empty user group";
  case AppdErrc::MissingUserGroupMembers:
    return "missing user group members";
  case AppdErrc::FeatureNotEnabled:
    return "feature not enabled";
  case AppdErrc::Conflict:
    return "conflict";
  case AppdErrc::InvalidAuthorizationCode:
    return "invalid authorization code";
  case AppdErrc::OidcProviderInteractionRequired:
    return "oidc provider interaction required";
  case AppdErrc::OidcProviderNotConfigured:
    return "oidc provider not configured";
  case AppdErrc::OidcProviderNotSupported:
    return "oidc provider not supported";
  }
  return "unknown error";
}

std::error_condition AppdErrcCategory::default_error_condition(int c) const noexcept
{
  switch (static_cast<AppdErrc>(c))
  {
  case AppdErrc::BadRequest:
  case AppdErrc::DeviceNotFound:
  case AppdErrc::InternalError:
  case AppdErrc::InvalidBody:
  case AppdErrc::InvalidChallengePublicKey:
  case AppdErrc::InvalidChallengeSignature:
  case AppdErrc::InvalidToken:
  case AppdErrc::ProvisionalIdentityNotFound:
  case AppdErrc::TrustchainIsNotTest:
  case AppdErrc::UnknownError:
  case AppdErrc::UserNotFound:
    return make_error_condition(Errors::Errc::InternalError);
  case AppdErrc::ProvisionalIdentityAlreadyAttached:
    return make_error_condition(Errors::Errc::IdentityAlreadyAttached);
  case AppdErrc::InvalidAuthorizationCode:
  case AppdErrc::InvalidDelegationSignature:
  case AppdErrc::InvalidPassphrase:
  case AppdErrc::InvalidVerificationCode:
  case AppdErrc::VerificationCodeNotFound:
    return make_error_condition(Errors::Errc::InvalidVerification);
  case AppdErrc::AppNotFound:
  case AppdErrc::Blocked:
  case AppdErrc::FeatureNotEnabled:
  case AppdErrc::OidcProviderInteractionRequired:
  case AppdErrc::OidcProviderNotConfigured:
  case AppdErrc::OidcProviderNotSupported:
  case AppdErrc::VerificationKeyNotFound:
  case AppdErrc::VerificationMethodNotSet:
    return make_error_condition(Errors::Errc::PreconditionFailed);
  case AppdErrc::TooManyAttempts:
    return make_error_condition(Errors::Errc::TooManyAttempts);
  case AppdErrc::VerificationCodeExpired:
    return make_error_condition(Errors::Errc::ExpiredVerification);
  case AppdErrc::GroupTooBig:
    return make_error_condition(Errors::Errc::GroupTooBig);
  case AppdErrc::UpgradeRequired:
    return make_error_condition(Errors::Errc::UpgradeRequired);
  case AppdErrc::EmptyUserGroup:
  case AppdErrc::MissingUserGroupMembers:
  case AppdErrc::NotAUserGroupMember:
    return make_error_condition(Errors::Errc::InvalidArgument);
  case AppdErrc::Conflict:
    return make_error_condition(Errors::Errc::Conflict);
  }
  return std::error_condition(c, *this);
}
}
}
