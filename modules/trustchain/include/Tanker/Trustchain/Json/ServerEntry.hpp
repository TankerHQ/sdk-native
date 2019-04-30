#pragma once

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Trustchain
{
class ServerEntry;

void to_json(nlohmann::json&, ServerEntry const&);
}
}
