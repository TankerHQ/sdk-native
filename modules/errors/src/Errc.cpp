#include <Tanker/Errors/Errc.hpp>

#include <Tanker/Errors/ErrcCategory.hpp>

namespace Tanker
{
namespace Errors
{
std::error_condition make_error_condition(Errc c) noexcept
{
  return {static_cast<int>(c), ErrcCategory()};
}

std::error_code make_error_code(Errc c) noexcept
{
  return std::error_code(static_cast<int>(c), ErrcCategory());
}
}
}
