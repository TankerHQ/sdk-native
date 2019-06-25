#pragma once

#include <system_error>
#include <type_traits>

namespace Tanker
{
namespace Server
{
enum class Errc
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
  UnknownError
};

std::error_code make_error_code(Errc c) noexcept;
}
}

namespace std
{
template <>
struct is_error_code_enum<::Tanker::Server::Errc> : std::true_type
{
};
}
