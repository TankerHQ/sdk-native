#include <Tanker/Verif/Errors/Errc.hpp>
#include <Tanker/Verif/Errors/ErrcCategory.hpp>

namespace Tanker
{
namespace Verif
{
std::error_code make_error_code(Errc c) noexcept
{
  return std::error_code(static_cast<int>(c), ErrcCategory());
}
}
}
