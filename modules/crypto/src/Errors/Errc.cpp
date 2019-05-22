#include <Tanker/Crypto/Errors/Errc.hpp>

#include <Tanker/Crypto/Errors/ErrcCategory.hpp>

namespace Tanker
{
namespace Crypto
{
std::error_code make_error_code(Errc c) noexcept
{
  return {static_cast<int>(c), ErrcCategory()};
}
}
}
