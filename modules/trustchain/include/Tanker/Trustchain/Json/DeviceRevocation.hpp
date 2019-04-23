#pragma once

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class DeviceRevocation;

void to_json(nlohmann::json&, DeviceRevocation const&);
}
}
}
