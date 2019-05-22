#pragma once

#include <flags/allow_flags.hpp>
#include <flags/flags.hpp>

namespace Tanker
{
namespace Unlock
{
enum class Method
{
  Email = 0x1,
  Password,
  VerificationKey,

  Last = VerificationKey,
};

using Methods = ::flags::flags<Method>;
}
}
ALLOW_FLAGS_FOR_ENUM(Tanker::Unlock::Method)
