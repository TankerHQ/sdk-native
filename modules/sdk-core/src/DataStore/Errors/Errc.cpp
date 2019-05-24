#include <Tanker/DataStore/Errors/Errc.hpp>
#include <Tanker/DataStore/Errors/ErrcCategory.hpp>

namespace Tanker
{
namespace DataStore
{
std::error_code make_error_code(Errc c) noexcept
{
  return std::error_code(static_cast<int>(c), ErrcCategory());
}
}
}
