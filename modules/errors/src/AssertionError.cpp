#include <Tanker/Errors/AssertionError.hpp>

#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Log/Log.hpp>

#include <cassert>

TLOG_CATEGORY(Assertion);

namespace Tanker
{
namespace Errors
{
AssertionError::AssertionError(std::string const& message) : Exception(make_error_code(Errc::InternalError), message)
{
  TERROR("{}", what());
  assert(false);
}
}
}
