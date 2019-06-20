#include <Tanker/Server/Errors/Errc.hpp>

#include <Tanker/Server/Errors/ErrcCategory.hpp>

namespace Tanker
{
namespace Server
{
std::error_code make_error_code(Errc c) noexcept
{
  return {static_cast<int>(c), ErrcCategory()};
}
}
}
