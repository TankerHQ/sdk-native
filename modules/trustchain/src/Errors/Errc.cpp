#include <Tanker/Trustchain/Errors/Errc.hpp>

#include <Tanker/Trustchain/Errors/ErrcCategory.hpp>

namespace Tanker
{
namespace Trustchain
{
std::error_code make_error_code(Errc c) noexcept
{
  return {static_cast<int>(c), ErrcCategory()};
}
}
}

