#ifdef __APPLE__
#include <TargetConditionals.h>
#if TARGET_IPHONE_SIMULATOR
#define BOOST_STACKTRACE_GNU_SOURCE_NOT_REQUIRED
#elif TARGET_OS_IPHONE
// stacktrace is broken on armv7/armv7s
#if __arm__
#define BOOST_STACKTRACE_USE_NOOP
#else
#define BOOST_STACKTRACE_GNU_SOURCE_NOT_REQUIRED
#endif
#elif TARGET_OS_MAC
#define BOOST_STACKTRACE_GNU_SOURCE_NOT_REQUIRED
#else
#error "Unknown Apple platform"
#endif
#endif

#include <Tanker/Errors/Exception.hpp>

#include <boost/stacktrace/frame.hpp>
#include <boost/stacktrace/stacktrace.hpp>
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
  : _errorCode(ec),
    _backtrace(backtraceAsString()),
    _message(formatError(ec, message))
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

std::string const& Exception::backtrace() const
{
  return _backtrace;
}

std::string Exception::backtraceAsString()
{
  std::ostringstream ss;
  ss << boost::stacktrace::stacktrace();
  return ss.str();
}
}
}
