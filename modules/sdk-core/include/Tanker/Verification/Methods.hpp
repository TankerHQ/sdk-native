#pragma once

#include <flags/allow_flags.hpp>
#include <flags/flags.hpp>

namespace Tanker
{
namespace Verification
{
enum class Method
{
  Email = 0x1,
  Passphrase,
  VerificationKey,
  OidcIdToken,
  PhoneNumber,
  PreverifiedEmail,
  PreverifiedPhoneNumber,
  E2ePassphrase,
  PreverifiedOidc,

  Last,
};

using Methods = ::flags::flags<Method>;
}
}
ALLOW_FLAGS_FOR_ENUM(Tanker::Verification::Method)
