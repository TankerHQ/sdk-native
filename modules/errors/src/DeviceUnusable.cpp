#include <Tanker/Errors/DeviceUnusable.hpp>

#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Log/Log.hpp>

#include <cassert>

TLOG_CATEGORY(DeviceUnusable);

namespace Tanker
{
namespace Errors
{
DeviceUnusable::DeviceUnusable(std::string const& message) : Exception(make_error_code(Errc::InternalError), message)
{
  TERROR("This device is unusable and will be re-created: {}", what());
}
}
}
