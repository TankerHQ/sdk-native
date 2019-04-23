#pragma once

#include <string>

namespace Tanker
{
namespace Identity
{
enum class TargetType
{
  Email = 0,
};
std::string to_string(TargetType s);
}
}
