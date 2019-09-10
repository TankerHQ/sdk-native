#include <Tanker/Errors/ServerErrc.hpp>

#include <Tanker/Errors/ServerErrcCategory.hpp>

namespace Tanker
{
namespace Errors
{
std::error_code make_error_code(ServerErrc c) noexcept
{
  return {static_cast<int>(c), ServerErrcCategory()};
}
}
}
