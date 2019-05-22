#include <Tanker/Serialization/Errors/Errc.hpp>

#include <Tanker/Serialization/Errors/ErrcCategory.hpp>

namespace Tanker
{
namespace Serialization
{
std::error_code make_error_code(Errc c) noexcept
{
  return {static_cast<int>(c), ErrcCategory()};
}
}
}
