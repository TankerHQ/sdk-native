#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation/v1.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class DeviceCreation2 : private DeviceCreation1
{
  using base_t = DeviceCreation1;

public:
  DeviceCreation2() = default;
  DeviceCreation2(Crypto::PublicSignatureKey const& ephemeralPublicSignatureKey,
                  UserId const& userId,
                  Crypto::Signature const& delegationSignature,
                  Crypto::PublicSignatureKey const& devicePublicSignatureKey,
                  Crypto::PublicEncryptionKey const& devicePublicEncryptionKey,
                  Crypto::Hash const& lastReset);
  DeviceCreation2(Crypto::PublicSignatureKey const& ephemeralPublicSignatureKey,
                  UserId const& userId,
                  Crypto::PublicSignatureKey const& devicePublicSignatureKey,
                  Crypto::PublicEncryptionKey const& devicePublicEncryptionKey,
                  Crypto::Hash const& lastReset);

  static constexpr auto const nature = Nature::DeviceCreation2;

  using base_t::ephemeralPublicSignatureKey;
  using base_t::userId;
  using base_t::delegationSignature;
  using base_t::publicSignatureKey;
  using base_t::publicEncryptionKey;
  using base_t::signatureData;
  using base_t::sign;

  Crypto::Hash const& lastReset() const;

  // throws if !lastReset().is_null()
  DeviceCreation1 const& asDeviceCreation1() const;

private:
  Crypto::Hash _lastReset;

  friend bool operator==(DeviceCreation2 const& lhs,
                         DeviceCreation2 const& rhs);
  friend void from_serialized(Serialization::SerializedSource&,
                              DeviceCreation2&);
  friend void to_json(nlohmann::json&, DeviceCreation2 const&);
  friend std::uint8_t* to_serialized(std::uint8_t*, DeviceCreation2 const&);
};

bool operator==(DeviceCreation2 const& lhs, DeviceCreation2 const& rhs);
bool operator!=(DeviceCreation2 const& lhs, DeviceCreation2 const& rhs);
}
}
}

#include <Tanker/Trustchain/Json/DeviceCreation/v2.hpp>
#include <Tanker/Trustchain/Serialization/DeviceCreation/v2.hpp>
