#pragma once

#include <string>

namespace Tanker::Identity
{
enum class TargetType
{
  Email,
  HashedEmail,
  PhoneNumber,
  HashedPhoneNumber,
};
std::string to_string(TargetType s);
TargetType to_target_type(std::string const& s);
}
