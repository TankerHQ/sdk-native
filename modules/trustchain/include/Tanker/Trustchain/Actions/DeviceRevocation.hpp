#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation/v1.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation/v2.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>

#include <boost/variant2/variant.hpp>
#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class DeviceRevocation
{
public:
  using v1 = DeviceRevocation1;
  using v2 = DeviceRevocation2;

  DeviceRevocation() = default;
  DeviceRevocation(v1 const&);
  DeviceRevocation(v2 const&);

  Nature nature() const;
  DeviceId const& deviceId() const;

  template <typename T>
  bool holds_alternative() const;

  template <typename T>
  T const& get() const;

  template <typename T>
  T const* get_if() const;

  template <typename Callable>
  decltype(auto) visit(Callable&&) const;

private:
  boost::variant2::variant<v1, v2> _variant;

  friend bool operator==(DeviceRevocation const&, DeviceRevocation const&);
  friend std::uint8_t* to_serialized(std::uint8_t*, DeviceRevocation const&);
  friend std::size_t serialized_size(DeviceRevocation const&);
  friend void to_json(nlohmann::json&, DeviceRevocation const&);
};

bool operator==(DeviceRevocation const&, DeviceRevocation const&);
bool operator!=(DeviceRevocation const&, DeviceRevocation const&);

// The nature is not present in the wired payload.
// Therefore there is no from_serialized overload for DeviceRevocation.
std::uint8_t* to_serialized(std::uint8_t*, DeviceRevocation const&);
std::size_t serialized_size(DeviceRevocation const&);

void to_json(nlohmann::json&, DeviceRevocation const&);

template <typename T>
bool DeviceRevocation::holds_alternative() const
{
  return boost::variant2::holds_alternative<T>(_variant);
}

template <typename T>
T const& DeviceRevocation::get() const
{
  return boost::variant2::get<T>(_variant);
}

template <typename T>
T const* DeviceRevocation::get_if() const
{
  return boost::variant2::get_if<T>(&_variant);
}

template <typename Callable>
decltype(auto) DeviceRevocation::visit(Callable&& c) const
{
  return boost::variant2::visit(std::forward<Callable>(c), _variant);
}
}
}
}
