#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>

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
  return mpark::visit([](auto const& a) { return a.nature; }, _variant);
}

DeviceId const& DeviceRevocation::deviceId() const
{
  return mpark::visit(
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
}
}
}
