#pragma once

#include <system_error>
#include <type_traits>

namespace Tanker
{
namespace Identity
{
enum class Errc
{
  InvalidUserId = 1,
  InvalidTrustchainId,
  InvalidTrustchainPrivateKey,
  InvalidPermanentIdentityTarget,
  InvalidProvisionalIdentityTarget,
  InvalidUserSecret,
  InvalidType,
  InvalidEmail,
  InvalidFormat,
  InvalidPhoneNumber,
};

std::error_code make_error_code(Errc c) noexcept;
}
}

namespace std
{
template <>
struct is_error_code_enum<::Tanker::Identity::Errc> : std::true_type
{
};
}
