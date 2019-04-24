#pragma once

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class KeyPublishToProvisionalUser;

void to_json(nlohmann::json&, KeyPublishToProvisionalUser const&);
}
}
}
