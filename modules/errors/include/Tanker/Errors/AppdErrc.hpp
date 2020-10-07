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
  DeviceRevoked,
  TooManyAttempts,
  InvalidToken,
  VerificationNeeded,
  InvalidPassphrase,
  InvalidVerificationCode,
  VerificationCodeExpired,
  VerificationCodeNotFound,
  VerificationMethodNotSet,
  VerificationKeyNotFound,
  InvalidDelegationSignature,
  UnknownError,
  UserNotFound,
  BlockLimitsExceeded,
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
