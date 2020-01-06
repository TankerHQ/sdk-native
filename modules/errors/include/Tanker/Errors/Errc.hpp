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
  InternalError,
  NetworkError,
  PreconditionFailed,
  OperationCanceled,
  DecryptionFailed,
  GroupTooBig,
  InvalidVerification,
  TooManyAttempts,
  ExpiredVerification,
  IOError,
  DeviceRevoked,

  Last,
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
