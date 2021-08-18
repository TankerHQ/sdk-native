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
TargetType to_public_target_type(std::string const& s);
TargetType to_secret_target_type(std::string const& s);
}
