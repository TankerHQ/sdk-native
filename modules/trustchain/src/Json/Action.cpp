#include <Tanker/Trustchain/Action.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
void to_json(nlohmann::json& j, Action const& a)
{
  a.visit([&](auto const& val) { j = val; });
}
}
}
