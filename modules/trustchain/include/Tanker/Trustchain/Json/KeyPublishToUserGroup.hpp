#pragma once

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class KeyPublishToUserGroup;

void to_json(nlohmann::json&, KeyPublishToUserGroup const&);
}
}
}
