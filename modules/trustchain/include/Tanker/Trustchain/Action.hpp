#pragma once

#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToDevice.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToProvisionalUser.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToUser.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToUserGroup.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>
#include <Tanker/Trustchain/Actions/TrustchainCreation.hpp>
#include <Tanker/Trustchain/Actions/UserGroupAddition.hpp>
#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>

#include <gsl-lite.hpp>
#include <mpark/variant.hpp>
#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace Tanker
{
namespace Trustchain
{
class Action
{
  using variant_t = mpark::variant<Actions::DeviceCreation,
                                   Actions::DeviceRevocation,
                                   Actions::KeyPublishToDevice,
                                   Actions::KeyPublishToProvisionalUser,
                                   Actions::KeyPublishToUser,
                                   Actions::KeyPublishToUserGroup,
                                   Actions::ProvisionalIdentityClaim,
                                   Actions::TrustchainCreation,
                                   Actions::UserGroupAddition,
                                   Actions::UserGroupCreation>;

public:
  Action() = default;

  // SFINAE is mandatory to prevent copy/move ctor hijacking
  template <typename Alternative,
            typename = std::enable_if_t<
                std::is_constructible<variant_t, Alternative>::value>>
  Action(Alternative&&);

  static Action deserialize(Actions::Nature, gsl::span<std::uint8_t const>);

  Actions::Nature nature() const;

  template <typename T>
  bool holdsAlternative() const;

  template <typename T>
  T const& get() const;

  template <typename T>
  T const* get_if() const;

  template <typename Callable>
  decltype(auto) visit(Callable&&) const;

private:
  variant_t _variant;

  friend bool operator==(Action const&, Action const&);
};

template <typename Alternative, typename>
Action::Action(Alternative&& val) : _variant(std::forward<Alternative>(val))
{
}

template <typename T>
bool Action::holdsAlternative() const
{
  return mpark::holds_alternative<T>(_variant);
}

template <typename T>
T const& Action::get() const
{
  return mpark::get<T>(_variant);
}

template <typename T>
T const* Action::get_if() const
{
  return mpark::get_if<T>(&_variant);
}

template <typename Callable>
decltype(auto) Action::visit(Callable&& c) const
{
  return mpark::visit(std::forward<Callable>(c), _variant);
}

bool operator==(Action const& lhs, Action const& rhs);
bool operator!=(Action const& lhs, Action const& rhs);

std::uint8_t* to_serialized(std::uint8_t* it, Action const& a);
std::size_t serialized_size(Action const& a);

void to_json(nlohmann::json& j, Action const& a);
}
}
