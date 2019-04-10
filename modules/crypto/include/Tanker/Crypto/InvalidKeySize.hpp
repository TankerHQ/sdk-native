#pragma once

#include <stdexcept>
#include <string>

namespace Tanker
{
namespace Crypto
{
class InvalidKeySize : public std::exception
{
public:
  InvalidKeySize(std::string const& msg) : _msg(msg)
  {
  }

  char const* what() const noexcept override
  {
    return _msg.c_str();
  }

private:
  std::string _msg;
};
}
}
