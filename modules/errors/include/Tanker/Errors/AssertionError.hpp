#pragma once

#include <Tanker/Errors/Exception.hpp>

#include <string>

namespace Tanker
{
namespace Errors
{
class AssertionError : public Exception
{
public:
  explicit AssertionError(std::string const& message);
};
}
}
