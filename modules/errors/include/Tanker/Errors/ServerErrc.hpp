#pragma once

#include <system_error>
#include <type_traits>

namespace Tanker
{
namespace Errors
{
enum class ServerErrc
{
  InternalError = 1,
  InvalidBody,
  InvalidOrigin,
  TrustchainIsNotTest,
  TrustchainNotFound,
  DeviceNotFound,
  DeviceRevoked,
  TooManyAttempts,
  VerificationNeeded,
  InvalidPassphrase,
  InvalidVerificationCode,
  VerificationCodeExpired,
  VerificationCodeNotFound,
  VerificationMethodNotSet,
  VerificationKeyNotFound,
  GroupTooBig,
  InvalidDelegationSignature,
  UnknownError,
  Conflict,
};

std::error_code make_error_code(ServerErrc c) noexcept;
}
}

namespace std
{
template <>
struct is_error_code_enum<::Tanker::Errors::ServerErrc> : std::true_type
{
};
}
