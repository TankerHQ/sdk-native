#pragma once

#include <system_error>
#include <type_traits>

namespace Tanker
{
namespace Verif
{
enum class Errc
{
  InvalidSignature,
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
