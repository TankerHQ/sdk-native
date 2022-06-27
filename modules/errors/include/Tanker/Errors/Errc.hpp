#pragma once

#include <system_error>
#include <type_traits>

namespace Tanker
{
namespace Errors
{
enum class Errc
{
  InvalidArgument = 1,
  InternalError = 2,
  NetworkError = 3,
  PreconditionFailed = 4,
  OperationCanceled = 5,
  DecryptionFailed = 6,
  GroupTooBig = 7,
  InvalidVerification = 8,
  TooManyAttempts = 9,
  ExpiredVerification = 10,
  IOError = 11,
  // RevokedDevice = 12
  Conflict = 13,
  UpgradeRequired = 14,
  IdentityAlreadyAttached = 15,

  Last = 16,
};

std::error_condition make_error_condition(Errc c) noexcept;
std::error_code make_error_code(Errc c) noexcept;
}
}

namespace std
{
template <>
struct is_error_condition_enum<::Tanker::Errors::Errc> : std::true_type
{
};
}
