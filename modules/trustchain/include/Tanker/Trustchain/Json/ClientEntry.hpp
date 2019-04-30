#pragma once

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Trustchain
{
class ClientEntry;

void to_json(nlohmann::json&, ClientEntry const&);
}
}
