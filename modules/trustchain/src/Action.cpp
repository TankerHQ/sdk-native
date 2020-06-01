#include <Tanker/Trustchain/Action.hpp>

#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation/v2.hpp>
#include <Tanker/Trustchain/Errors/Errc.hpp>

#include <nlohmann/json.hpp>

#include <stdexcept>

using namespace Tanker::Trustchain::Actions;

namespace Tanker
{
namespace Trustchain
{
Action Action::deserialize(Nature nature, gsl::span<std::uint8_t const> payload)
{
  switch (nature)
  {
  case Nature::UserGroupCreation:
  case Nature::UserGroupAddition:
  case Nature::UserGroupCreation2:
  case Nature::UserGroupAddition2:
  case Nature::TrustchainCreation:
    throw Errors::AssertionError(fmt::format(
        "{} is not supported through this code path anymore", nature));
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
  case Nature::KeyPublishToUserGroup:
    return Serialization::deserialize<KeyPublishToUserGroup>(payload);
  case Nature::ProvisionalIdentityClaim:
    return Serialization::deserialize<ProvisionalIdentityClaim>(payload);
  case Nature::KeyPublishToDevice:
    throw Errors::formatEx(
        Errc::InvalidBlockNature, TFMT("{} is not supported anymore"), nature);
  }
  throw Errors::formatEx(
      Errc::InvalidBlockNature, TFMT("unkown action nature: {:d}"), nature);
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

std::uint8_t* to_serialized(std::uint8_t* it, Action const& a)
{
  return a.visit(
      [it](auto const& val) { return Serialization::serialize(it, val); });
}

std::size_t serialized_size(Action const& a)
{
  return a.visit(
      [](auto const& val) { return Serialization::serialized_size(val); });
}

void to_json(nlohmann::json& j, Action const& a)
{
  a.visit([&](auto const& val) { j = val; });
}
}
}
