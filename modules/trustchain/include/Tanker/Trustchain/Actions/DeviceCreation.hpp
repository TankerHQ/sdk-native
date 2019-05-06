#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation/v1.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation/v3.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/UserId.hpp>

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
class DeviceCreation
{
public:
  // v2 is missing, it's on purpose. We removed the "reset" feature, and v2 can
  // be converted into a v1 if the lastReset field is zero-filled.
  using v1 = DeviceCreation1;
  using v3 = DeviceCreation3;

  using DeviceType = v3::DeviceType;

  DeviceCreation() = default;
  DeviceCreation(v1 const&);
  DeviceCreation(v3 const&);

  Nature nature() const;
  Crypto::PublicSignatureKey const& ephemeralPublicSignatureKey() const;
  UserId const& userId() const;
  Crypto::Signature const& delegationSignature() const;
  Crypto::PublicSignatureKey const& publicSignatureKey() const;
  Crypto::PublicEncryptionKey const& publicEncryptionKey() const;
  bool isGhostDevice() const;

  std::vector<std::uint8_t> signatureData() const;
  Crypto::Signature const& sign(Crypto::PrivateSignatureKey const&);

  template <typename T>
  bool holdsAlternative() const;

  template <typename T>
  T const& get() const;

  template <typename T>
  T const* get_if() const;

  template <typename Callable>
  decltype(auto) visit(Callable&&) const;

private:
  mpark::variant<v1, v3> _variant;

  friend bool operator==(DeviceCreation const&, DeviceCreation const&);
  friend std::uint8_t* to_serialized(std::uint8_t*, DeviceCreation const&);
  friend std::size_t serialized_size(DeviceCreation const&);
  friend void to_json(nlohmann::json&, DeviceCreation const&);
};

bool operator==(DeviceCreation const&, DeviceCreation const&);
bool operator!=(DeviceCreation const&, DeviceCreation const&);

std::uint8_t* to_serialized(std::uint8_t* it, DeviceCreation const& dc);
std::size_t serialized_size(DeviceCreation const& dc);

void to_json(nlohmann::json& j, DeviceCreation const& dc);

template <typename T>
bool DeviceCreation::holdsAlternative() const
{
  return mpark::holds_alternative<T>(_variant);
}

template <typename T>
T const& DeviceCreation::get() const
{
  return mpark::get<T>(_variant);
}

template <typename T>
T const* DeviceCreation::get_if() const
{
  return mpark::get_if<T>(&_variant);
}

template <typename Callable>
decltype(auto) DeviceCreation::visit(Callable&& c) const
{
  return mpark::visit(std::forward<Callable>(c), _variant);
}
}
}
}
