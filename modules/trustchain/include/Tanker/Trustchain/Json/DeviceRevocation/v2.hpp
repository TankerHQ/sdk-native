#pragma once

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class DeviceRevocation2;

void to_json(nlohmann::json&, DeviceRevocation2 const&);
}
}
}
