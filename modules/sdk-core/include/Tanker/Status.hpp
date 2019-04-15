#pragma once

#include <string>
#include <type_traits>

namespace Tanker
{
enum class Status
{
  Closed,
  Open,
  Last
};

std::string to_string(Status s);
}
