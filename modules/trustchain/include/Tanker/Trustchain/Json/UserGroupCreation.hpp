#pragma once

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class UserGroupCreation;

void to_json(nlohmann::json&, UserGroupCreation const&);
}
}
}
