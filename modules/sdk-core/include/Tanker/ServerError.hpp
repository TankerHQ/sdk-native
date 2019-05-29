#pragma once

#include <Tanker/Errors/Exception.hpp>

#include <string>

namespace Tanker
{
class ServerError : public Errors::Exception
{
public:
  ServerError(int httpStatus,
              std::string const& errorCode,
              std::string const& message);
  ServerError(std::string const& eventName,
              int httpStatus,
              std::string const& errorCode,
              std::string const& message);

  int httpStatusCode() const;

  std::string const& serverCode() const;
  std::string const& message() const;

private:
  int _httpStatusCode;
  std::string _errorCode;
  std::string _message;
};
}
