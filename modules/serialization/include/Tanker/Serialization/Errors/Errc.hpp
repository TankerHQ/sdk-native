#pragma once

#include <system_error>
#include <type_traits>

namespace Tanker
{
namespace Serialization
{
enum class Errc
{
  TrailingInput,
  TruncatedInput,
};

std::error_code make_error_code(Errc) noexcept;
}
}

namespace std
{
template <>
struct is_error_code_enum<::Tanker::Serialization::Errc> : std::true_type
{
};
}
