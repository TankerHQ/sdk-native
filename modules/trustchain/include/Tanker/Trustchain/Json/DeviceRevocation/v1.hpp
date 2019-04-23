#pragma once

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class DeviceRevocation1;

void to_json(nlohmann::json&, DeviceRevocation1 const&);
}
}
}
