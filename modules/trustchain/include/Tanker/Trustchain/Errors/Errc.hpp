#pragma once

#include <system_error>
#include <type_traits>

namespace Tanker
{
namespace Trustchain
{
enum class Errc
{
  InvalidBlockVersion = 1,
  InvalidBlockNature,
  InvalidLastResetField,
};

std::error_code make_error_code(Errc c) noexcept;
}
}

namespace std
{
template <>
struct is_error_code_enum<::Tanker::Trustchain::Errc> : std::true_type
{
};
}
