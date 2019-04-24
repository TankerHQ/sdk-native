#pragma once

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Trustchain
{
class Action;

void to_json(nlohmann::json&, Action const&);
}
}
