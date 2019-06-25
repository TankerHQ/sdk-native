#include <Tanker/Crypto/Errors/Exception.hpp>

#include <utility>

namespace Tanker
{
namespace Crypto
{
Exception::Exception(std::error_code ec)
  : Errors::Exception(ec.default_error_condition(), ec.message()),
    _errorCode(ec)
{
}

Exception::Exception(std::error_code ec, std::string message)
  : Errors::Exception(ec.default_error_condition(), std::move(message)),
    _errorCode(ec)
{
}

std::error_code const& Exception::errorCode() const
{
  return _errorCode;
}
}
}
