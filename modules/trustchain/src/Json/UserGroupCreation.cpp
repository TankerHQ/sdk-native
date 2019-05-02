#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void to_json(nlohmann::json& j, UserGroupCreation const& dc)
{
  mpark::visit([&j](auto const& val) { j = val; }, dc._variant);
}
}
}
}
