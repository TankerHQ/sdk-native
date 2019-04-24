#include <Tanker/Action.hpp>

#include <Tanker/Error.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation/v2.hpp>

#include <fmt/format.h>
#include <mpark/variant.hpp>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <vector>

using Tanker::Trustchain::Actions::Nature;

namespace Tanker
{
namespace
{
struct MakeIndexesVisitor
{
  template <typename T>
  auto operator()(T const& val) const
  {
    return val.makeIndexes();
  }

  auto operator()(Trustchain::Actions::DeviceCreation const& dc) const
  {
    auto const& id = dc.userId();
    auto const& key = dc.publicSignatureKey();

    return std::vector<Index>{
        Index{IndexType::UserId, {id.begin(), id.end()}},
        Index{IndexType::DevicePublicSignatureKey, {key.begin(), key.end()}}};
  }

  auto operator()(Trustchain::Actions::DeviceRevocation const& dr) const
  {
    return std::vector<Index>{};
  }

  auto operator()(Trustchain::Actions::KeyPublishToDevice const& kp) const
  {
    return std::vector<Index>{};
  }

  auto operator()(Trustchain::Actions::KeyPublishToUserGroup const& kp) const
  {
    return std::vector<Index>{};
  }

  auto operator()(Trustchain::Actions::UserGroupCreation const& ugc) const
  {
    return std::vector<Index>{};
  }

  auto operator()(Trustchain::Actions::UserGroupAddition const& uga) const
  {
    return std::vector<Index>{};
  }

  auto operator()(Trustchain::Actions::KeyPublishToUser const& kp) const
  {
    return std::vector<Index>{};
  }

  auto operator()(Trustchain::Actions::TrustchainCreation const&) const
  {
    return std::vector<Index>{};
  }
};
}

std::uint8_t* to_serialized(std::uint8_t* it, Action const& dr)
{
  return Serialization::serialize(it, dr.variant());
}

Action deserializeAction(Nature nature, gsl::span<uint8_t const> payload)
{
  using namespace Trustchain::Actions;

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
    return Action{deserializeKeyPublishToProvisionalUser(payload)};
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
    return Action{deserializeProvisionalIdentityClaim(payload)};
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
  return mpark::visit(MakeIndexesVisitor{}, _v);
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
