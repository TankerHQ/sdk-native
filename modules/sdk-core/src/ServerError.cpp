#include <Tanker/ServerError.hpp>

#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Format/Format.hpp>

#include <fmt/format.h>

namespace Tanker
{
ServerError::ServerError(std::string const& eventName,
                         int httpStatus,
                         std::string const& errorCode,
                         std::string const& message)
  : Exception(make_error_code(Errors::Errc::InternalError),
              fmt::format(TFMT("error on emit({:s}): status: {:d}, "
                          "errorCode: {:s}"),
                          eventName,
                          httpStatus,
                          errorCode)),
    _httpStatusCode(httpStatus),
    _errorCode(errorCode),
    _message(message)
{
}

ServerError::ServerError(int httpStatus,
                         std::string const& errorCode,
                         std::string const& message)
  : Exception(make_error_code(Errors::Errc::InternalError),
              fmt::format(TFMT("ServerError: status: {:d}, errorCode: {:s}"),
                          httpStatus,
                          errorCode)),
    _httpStatusCode(httpStatus),
    _errorCode(errorCode),
    _message(message)
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
}
