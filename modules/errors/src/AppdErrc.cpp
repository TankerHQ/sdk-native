#include <Tanker/Errors/AppdErrc.hpp>

#include <Tanker/Errors/AppdErrcCategory.hpp>

namespace Tanker::Errors
{
std::error_code make_error_code(AppdErrc c) noexcept
{
  return {static_cast<int>(c), AppdErrcCategory()};
}
}