#pragma once

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class UserGroupCreation1;

void to_json(nlohmann::json&, UserGroupCreation1 const&);
}
}
}
