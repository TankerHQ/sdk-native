#include <Tanker/Trustchain/Action.hpp>

#include <Tanker/Format/Enum.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation/v2.hpp>

#include <fmt/format.h>

using namespace Tanker::Trustchain::Actions;

namespace Tanker
{
namespace Trustchain
{
Action Action::deserialize(Nature nature, gsl::span<std::uint8_t const> payload)
{
  switch (nature)
  {
  case Nature::TrustchainCreation:
    return Serialization::deserialize<TrustchainCreation>(payload);
  case Nature::KeyPublishToDevice:
    return Serialization::deserialize<KeyPublishToDevice>(payload);
  // how does this compile and work since there is a double implicit conversion
  // which cannot compile!? you might ask. Because variant is tricky, look at
  // constructor 4: https://en.cppreference.com/w/cpp/utility/variant/variant
  case Nature::DeviceCreation:
    return Serialization::deserialize<DeviceCreation::v1>(payload);
  case Nature::DeviceCreation2:
    return Serialization::deserialize<DeviceCreation2>(payload)
        .asDeviceCreation1();
  case Nature::DeviceCreation3:
    return Serialization::deserialize<DeviceCreation::v3>(payload);
  case Nature::KeyPublishToUser:
    return Serialization::deserialize<KeyPublishToUser>(payload);
  case Nature::KeyPublishToProvisionalUser:
    return Serialization::deserialize<KeyPublishToProvisionalUser>(payload);
  case Nature::DeviceRevocation:
    return Serialization::deserialize<DeviceRevocation1>(payload);
  case Nature::DeviceRevocation2:
    return Serialization::deserialize<DeviceRevocation2>(payload);
  case Nature::UserGroupCreation:
    return Serialization::deserialize<UserGroupCreation1>(payload);
  case Nature::KeyPublishToUserGroup:
    return Serialization::deserialize<KeyPublishToUserGroup>(payload);
  case Nature::UserGroupAddition:
    return Serialization::deserialize<UserGroupAddition>(payload);
  case Nature::ProvisionalIdentityClaim:
    return Serialization::deserialize<ProvisionalIdentityClaim>(payload);
  }
  throw std::runtime_error{fmt::format(fmt("unknown nature: {:d}"), nature)};
}

Nature Action::nature() const
{
  return this->visit([](auto const& a) { return a.nature(); });
}

bool operator==(Action const& lhs, Action const& rhs)
{
  return lhs._variant == rhs._variant;
}

bool operator!=(Action const& lhs, Action const& rhs)
{
  return !(lhs == rhs);
}
}
}
