#pragma once

#include <system_error>
#include <type_traits>

namespace Tanker
{
namespace Verif
{
enum class Errc
{
  InvalidSignature = 1,
  InvalidAuthor,
  InvalidHash,
  InvalidUserKey,
  InvalidLastReset,
  InvalidUserId,
  InvalidDelegationSignature,
  InvalidUser,
  InvalidEncryptionKey,
  InvalidGroup,
  InvalidUserKeys,
  InvalidTargetDevice,
  UserAlreadyExists,
};

std::error_code make_error_code(Errc c) noexcept;
}
}

namespace std
{
template <>
struct is_error_code_enum<::Tanker::Verif::Errc> : std::true_type
{
};
}
