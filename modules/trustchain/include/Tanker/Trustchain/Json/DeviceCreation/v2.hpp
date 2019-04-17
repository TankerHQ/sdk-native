#pragma once

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class DeviceCreation2;

void to_json(nlohmann::json&, DeviceCreation2 const&);
}
}
}
