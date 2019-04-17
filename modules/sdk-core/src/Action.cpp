#include <Tanker/Action.hpp>

#include <Tanker/Format/Enum.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <fmt/format.h>
#include <mpark/variant.hpp>
#include <nlohmann/json.hpp>


#include <cstdint>
#include <vector>

using Tanker::Trustchain::Actions::Nature;

namespace Tanker
{
std::uint8_t* to_serialized(std::uint8_t* it, Action const& dr)
{
  return Serialization::serialize(it, dr.variant());
}

Action deserializeAction(Nature nature, gsl::span<uint8_t const> payload)
{
  switch (nature)
  {
  case Nature::TrustchainCreation:
    return Action{Serialization::deserialize<TrustchainCreation>(payload)};
  case Nature::KeyPublishToDevice:
    return Action{deserializeKeyPublishToDevice(payload)};
  case Nature::DeviceCreation:
    return Action{
        DeviceCreation{Serialization::deserialize<DeviceCreation1>(payload)}};
  case Nature::DeviceCreation2:
    // Deserialize DeviceCreation2 as DeviceCreation1 (skip the lastReset
    // field):
    return Action{DeviceCreation{Serialization::deserialize<DeviceCreation1>(
        payload.subspan(Crypto::Hash::arraySize))}};
  case Nature::DeviceCreation3:
    return Action{
        DeviceCreation{Serialization::deserialize<DeviceCreation3>(payload)}};
  case Nature::KeyPublishToUser:
    return Action{deserializeKeyPublishToUser(payload)};
  case Nature::KeyPublishToProvisionalUser:
    return Action{deserializeKeyPublishToProvisionalUser(payload)};
  case Nature::DeviceRevocation:
    return Action{DeviceRevocation{
        Serialization::deserialize<DeviceRevocation1>(payload)}};
  case Nature::DeviceRevocation2:
    return Action{DeviceRevocation{
        Serialization::deserialize<DeviceRevocation2>(payload)}};
  case Nature::UserGroupCreation:
    return Action{deserializeUserGroupCreation(payload)};
  case Nature::KeyPublishToUserGroup:
    return Action{deserializeKeyPublishToUserGroup(payload)};
  case Nature::UserGroupAddition:
    return Action{deserializeUserGroupAddition(payload)};
  }
  throw Error::formatEx<Error::UnexpectedBlock>(fmt("unknown nature: {:d}"),
                                                nature);
}

Action::Action(variant_type&& v) : _v(std::move(v))
{
}

Action::Action(variant_type const& v) : _v(v)
{
}

Action& Action::operator=(variant_type&& v)
{
  _v = std::move(v);
  return *this;
}

Action& Action::operator=(variant_type const& v)
{
  _v = v;
  return *this;
}

auto Action::variant() const -> variant_type const&
{
  return _v;
}

Nature Action::nature() const
{
  return mpark::visit([](auto const& v) { return v.nature(); }, _v);
}

std::vector<Index> Action::makeIndexes() const
{
  return mpark::visit([](auto const& v) { return v.makeIndexes(); }, _v);
}

void to_json(nlohmann::json& j, Action const& r)
{
  mpark::visit([&](auto const& o) { j = o; }, r.variant());
}

std::size_t serialized_size(Action const& r)
{
  return Serialization::serialized_size(r.variant());
}

bool operator==(Action const& lhs, Action const& rhs)
{
  return lhs.variant() == rhs.variant();
}

bool operator!=(Action const& lhs, Action const& rhs)
{
  return !(lhs == rhs);
}
}
