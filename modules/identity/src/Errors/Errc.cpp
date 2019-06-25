#include <Tanker/Identity/Errors/Errc.hpp>

#include <Tanker/Identity/Errors/ErrcCategory.hpp>

namespace Tanker
{
namespace Identity
{
std::error_code make_error_code(Errc c) noexcept
{
  return {static_cast<int>(c), ErrcCategory()};
}
}
}
