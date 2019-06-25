#pragma once

#include <string>
#include <type_traits>

namespace Tanker
{
enum class Status
{
  Stopped,
  Ready,
  IdentityRegistrationNeeded,
  IdentityVerificationNeeded,
  Last
};

std::string to_string(Status s);
}
