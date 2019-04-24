#pragma once

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class UserGroupAddition;

void to_json(nlohmann::json&, UserGroupAddition const&);
}
}
}
