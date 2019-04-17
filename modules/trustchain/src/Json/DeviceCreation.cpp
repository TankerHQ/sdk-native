#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void to_json(nlohmann::json& j, DeviceCreation const& dc)
{
  mpark::visit([&j](auto const& val) { j = val; }, dc._variant);
}
}
}
}
