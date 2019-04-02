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

#ifdef EMSCRIPTEN
#define BOOST_STACKTRACE_USE_NOOP
#endif

#include <Tanker/Error.hpp>

#include <Tanker/EnumFormat.hpp>
#include <Tanker/Log.hpp>

#include <boost/stacktrace/frame.hpp>
#include <boost/stacktrace/stacktrace.hpp>
#include <fmt/format.h>

#include <sstream>

TLOG_CATEGORY(Exception);

namespace Tanker
{
namespace Error
{
Exception::Exception(Code code, std::string message)
  : _code(code),
    _message(std::move(message)),
    _backtrace(backtraceAsString()),
    _buffer(fmt::format("{:d}: {:s}", static_cast<int>(_code), _message))
{
  TERROR("{}", _buffer);
}

char const* Exception::what() const noexcept
{
  return _buffer.c_str();
}

Code Exception::code() const
{
  return _code;
}

std::string const& Exception::message() const
{
  return _message;
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

ServerError::ServerError(std::string eventName,
                         int httpStatus,
                         std::string errorCode,
                         std::string message)
  : Exception(Code::ServerError,
              fmt::format("error on emit({}): status: {}, "
                          "errorCode: {}",
                          eventName,
                          httpStatus,
                          errorCode)),
    _errorCode(std::move(errorCode)),
    _message(std::move(message)),
    _httpStatusCode(httpStatus)
{
}

ServerError::ServerError(int httpStatus,
                         std::string errorCode,
                         std::string message)
  : Exception(
        Code::ServerError,
        fmt::format(
            "ServerError: status: {httpStatus:d}, errorCode: {errorCode:s}",
            fmt::arg("httpStatusCode", httpStatus),
            fmt::arg("errorCode", errorCode))),
    _errorCode(std::move(errorCode)),
    _message(std::move(message)),
    _httpStatusCode(httpStatus)
{
}

int ServerError::httpStatusCode() const
{
  return _httpStatusCode;
}

std::string const& ServerError::serverCode() const
{
  return _errorCode;
}

std::string const& ServerError::message() const
{
  return _message;
}

VerificationFailed::VerificationFailed(VerificationCode code,
                                       std::string message)
  : InternalError(fmt::format("{}: {}", code, message)), _code(code)
{
}

VerificationCode VerificationFailed::code() const
{
  return _code;
}

std::string to_string(VerificationCode code)
{
#define CASE(ARG)             \
  case VerificationCode::ARG: \
    return #ARG

  switch (code)
  {
    CASE(InvalidSignature);
    CASE(InvalidAuthor);
    CASE(InvalidHash);
    CASE(InvalidUserKey);
    CASE(InvalidLastReset);
    CASE(InvalidUserId);
    CASE(InvalidDelegationSignature);
    CASE(InvalidUser);
    CASE(InvalidEncryptionKey);
    CASE(InvalidGroup);
    CASE(InvalidUserKeys);
    CASE(InvalidTargetDevice);
  }
#undef CASE
  return "INVALID";
}
}
}
