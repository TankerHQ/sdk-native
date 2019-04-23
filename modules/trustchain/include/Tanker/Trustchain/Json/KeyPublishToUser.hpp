#pragma once

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class KeyPublishToUser;

void to_json(nlohmann::json&, KeyPublishToUser const&);
}
}
}
