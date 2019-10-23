#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
DeviceRevocation::DeviceRevocation(v1 const& dr1) : _variant(dr1)
{
}

DeviceRevocation::DeviceRevocation(v2 const& dr2) : _variant(dr2)
{
}

Nature DeviceRevocation::nature() const
{
  return boost::variant2::visit([](auto const& a) { return a.nature(); },
                                _variant);
}

DeviceId const& DeviceRevocation::deviceId() const
{
  return boost::variant2::visit(
      [](auto const& a) -> decltype(auto) { return a.deviceId(); }, _variant);
}

bool operator==(DeviceRevocation const& lhs, DeviceRevocation const& rhs)
{
  return lhs._variant == rhs._variant;
}

bool operator!=(DeviceRevocation const& lhs, DeviceRevocation const& rhs)
{
  return !(lhs == rhs);
}

std::uint8_t* to_serialized(std::uint8_t* it, DeviceRevocation const& dc)
{
  return Serialization::serialize(it, dc._variant);
}

std::size_t serialized_size(DeviceRevocation const& dc)
{
  return Serialization::serialized_size(dc._variant);
}

void to_json(nlohmann::json& j, DeviceRevocation const& dr)
{
  boost::variant2::visit([&j](auto const& val) { j = val; }, dr._variant);
}
}
}
}
