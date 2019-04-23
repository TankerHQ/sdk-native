#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void to_json(nlohmann::json& j, DeviceRevocation const& dr)
{
  mpark::visit([&j](auto const& val) { j = val; }, dr._variant);
}
}
}
}
