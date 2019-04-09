#pragma once

#include <Tanker/Actions/DeviceCreation.hpp>
#include <Tanker/Actions/DeviceRevocation.hpp>
#include <Tanker/Actions/KeyPublishToDevice.hpp>
#include <Tanker/Actions/KeyPublishToUser.hpp>
#include <Tanker/Actions/KeyPublishToUserGroup.hpp>
#include <Tanker/Actions/TrustchainCreation.hpp>
#include <Tanker/Actions/UserGroupAddition.hpp>
#include <Tanker/Actions/UserGroupCreation.hpp>
#include <Tanker/Nature.hpp>

#include <gsl-lite.hpp>
#include <mpark/variant.hpp>
#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <vector>

namespace Tanker
{
class Action
{
public:
  using variant_type = mpark::variant<TrustchainCreation,
                                      DeviceCreation,
                                      KeyPublishToDevice,
                                      DeviceRevocation,
                                      KeyPublishToUser,
                                      UserGroupCreation,
                                      KeyPublishToUserGroup,
                                      UserGroupAddition>;

  explicit Action(variant_type&&);
  explicit Action(variant_type const&);

  Action& operator=(variant_type&&);
  Action& operator=(variant_type const&);

  Action() = default;
  Action(Action const&) = default;
  Action(Action&&) = default;
  Action& operator=(Action const&) = default;
  Action& operator=(Action&&) = default;

  variant_type const& variant() const;

  Nature nature() const;

  std::vector<Index> makeIndexes() const;

private:
  variant_type _v;
};

bool operator==(Action const& l, Action const& r);
bool operator!=(Action const& l, Action const& r);

std::uint8_t* to_serialized(std::uint8_t* it, Action const& dr);
std::size_t serialized_size(Action const&);

// we do not use from_serialized here, because the nature is not serialized in
// the payload.
Action deserializeAction(Nature nature, gsl::span<uint8_t const> data);

void to_json(nlohmann::json& j, Action const& dc);
}
