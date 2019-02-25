#pragma once

#include <Tanker/EnumTrait.hpp>

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

template <>
struct is_enum_type<Status> : std::true_type
{
};
}
