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
    return Action{Serialization::deserialize<TrustchainCreation>(payload)};
  case Nature::KeyPublishToDevice:
    return Action{Serialization::deserialize<KeyPublishToDevice>(payload)};
  case Nature::DeviceCreation:
    return Action{DeviceCreation{
        Serialization::deserialize<DeviceCreation::v1>(payload)}};
  case Nature::DeviceCreation2:
    return Action{
        DeviceCreation{Serialization::deserialize<DeviceCreation2>(payload)
                           .asDeviceCreation1()}};
  case Nature::DeviceCreation3:
    return Action{DeviceCreation{
        Serialization::deserialize<DeviceCreation::v3>(payload)}};
  case Nature::KeyPublishToUser:
    return Action{Serialization::deserialize<KeyPublishToUser>(payload)};
  case Nature::KeyPublishToProvisionalUser:
    return Action{
        Serialization::deserialize<KeyPublishToProvisionalUser>(payload)};
  case Nature::DeviceRevocation:
    return Action{DeviceRevocation{
        Serialization::deserialize<DeviceRevocation1>(payload)}};
  case Nature::DeviceRevocation2:
    return Action{DeviceRevocation{
        Serialization::deserialize<DeviceRevocation2>(payload)}};
  case Nature::UserGroupCreation:
    return Action{Serialization::deserialize<UserGroupCreation>(payload)};
  case Nature::KeyPublishToUserGroup:
    return Action{Serialization::deserialize<KeyPublishToUserGroup>(payload)};
  case Nature::UserGroupAddition:
    return Action{Serialization::deserialize<UserGroupAddition>(payload)};
  case Nature::ProvisionalIdentityClaim:
    return Action{
        Serialization::deserialize<ProvisionalIdentityClaim>(payload)};
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
