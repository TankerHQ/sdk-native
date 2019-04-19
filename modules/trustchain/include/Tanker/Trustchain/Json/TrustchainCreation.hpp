#pragma once

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class TrustchainCreation;

void to_json(nlohmann::json&, TrustchainCreation const&);
}
}
}
