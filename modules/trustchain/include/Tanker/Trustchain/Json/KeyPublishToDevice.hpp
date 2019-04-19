#pragma once

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class KeyPublishToDevice;

void to_json(nlohmann::json&, KeyPublishToDevice const&);
}
}
}
