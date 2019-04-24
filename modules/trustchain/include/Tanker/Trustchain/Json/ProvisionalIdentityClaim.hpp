#pragma once

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class ProvisionalIdentityClaim;

void to_json(nlohmann::json&, ProvisionalIdentityClaim const&);
}
}
}
