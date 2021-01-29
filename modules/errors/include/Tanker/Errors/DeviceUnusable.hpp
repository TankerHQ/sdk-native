#pragma once

#include <Tanker/Errors/Exception.hpp>

#include <string>

namespace Tanker
{
namespace Errors
{
class DeviceUnusable : public Exception
{
public:
  explicit DeviceUnusable(std::string const& message);
};
}
}
