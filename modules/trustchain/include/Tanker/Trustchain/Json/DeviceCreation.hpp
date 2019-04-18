#pragma once

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class DeviceCreation;

void to_json(nlohmann::json&, DeviceCreation const&);
}
}
}
