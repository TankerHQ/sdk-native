#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation/v1.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation/v2.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>

#include <mpark/variant.hpp>
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
  bool holdsAlternative() const;

  template <typename T>
  T const& get() const;

  template <typename T>
  T const* get_if() const;

  template <typename Callable>
  decltype(auto) visit(Callable&&) const;

private:
  mpark::variant<v1, v2> _variant;

  friend bool operator==(DeviceRevocation const&, DeviceRevocation const&);
  friend std::uint8_t* to_serialized(std::uint8_t*, DeviceRevocation const&);
  friend std::size_t serialized_size(DeviceRevocation const&);
  friend void to_json(nlohmann::json&, DeviceRevocation const&);
};

bool operator==(DeviceRevocation const&, DeviceRevocation const&);
bool operator!=(DeviceRevocation const&, DeviceRevocation const&);

template <typename T>
bool DeviceRevocation::holdsAlternative() const
{
  return mpark::holds_alternative<T>(_variant);
}

template <typename T>
T const& DeviceRevocation::get() const
{
  return mpark::get<T>(_variant);
}

template <typename T>
T const* DeviceRevocation::get_if() const
{
  return mpark::get_if<T>(&_variant);
}

template <typename Callable>
decltype(auto) DeviceRevocation::visit(Callable&& c) const
{
  return mpark::visit(std::forward<Callable>(c), _variant);
}
}
}
}

#include <Tanker/Trustchain/Json/DeviceRevocation.hpp>
#include <Tanker/Trustchain/Serialization/DeviceRevocation.hpp>
