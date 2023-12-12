#pragma once

#include <system_error>
#include <type_traits>

namespace Tanker::Errors
{
enum class AppdErrc
{
  InternalError = 1,
  InvalidBody,
  GroupTooBig,
  TrustchainIsNotTest,
  AppNotFound,
  DeviceNotFound,
  ProvisionalIdentityNotFound,
  ProvisionalIdentityAlreadyAttached,
  TooManyAttempts,
  InvalidToken,
  _Deprecated_VerificationNeeded, // don't delete, this would change the next
                                  // values
  InvalidPassphrase,
  InvalidVerificationCode,
  VerificationCodeExpired,
  VerificationCodeNotFound,
  VerificationMethodNotSet,
  VerificationKeyNotFound,
  InvalidDelegationSignature,
  UnknownError,
  UserNotFound,
  Blocked,
  UpgradeRequired,
  BadRequest,
  InvalidChallengePublicKey,
  InvalidChallengeSignature,
  NotAUserGroupMember,
  EmptyUserGroup,
  MissingUserGroupMembers,
  FeatureNotEnabled,
  Conflict,
};

std::error_code make_error_code(AppdErrc) noexcept;
}

namespace std
{
template <>
struct is_error_code_enum<::Tanker::Errors::AppdErrc> : std::true_type
{
};
}
