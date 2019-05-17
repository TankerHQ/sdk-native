#pragma once

#include <flags/allow_flags.hpp>
#include <flags/flags.hpp>

#include <nlohmann/json_fwd.hpp>

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

void to_json(nlohmann::json&, Methods);
void from_json(nlohmann::json const&, Methods&);
}
}
ALLOW_FLAGS_FOR_ENUM(Tanker::Unlock::Method)
