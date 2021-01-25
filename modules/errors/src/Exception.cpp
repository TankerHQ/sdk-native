#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

#include <Tanker/Errors/Exception.hpp>

#include <fmt/format.h>

#include <sstream>
#include <utility>

namespace Tanker
{
namespace Errors
{

TANKER_WARN_UNUSED_RESULT Exception formatEx(std::error_code ec,
                                             fmt::string_view format,
                                             fmt::format_args args)
{
  return Exception(ec, fmt::vformat(format, args));
}

Exception::Exception(std::error_code ec) : Exception(ec, ec.message())
{
}

Exception::Exception(std::error_code ec, std::string const& message)
  : _errorCode(ec), _message(formatError(ec, message))
{
}

std::string Exception::formatError(std::error_code ec,
                                   std::string const& message)
{
  return fmt::format(FMT_STRING("{:s}::{:s}({:s}): {:s}"),
                     ec.default_error_condition().category().name(),
                     ec.category().name(),
                     ec.message(),
                     message);
}

char const* Exception::what() const noexcept
{
  return _message.c_str();
}

std::error_code const& Exception::errorCode() const
{
  return _errorCode;
}
}
}
