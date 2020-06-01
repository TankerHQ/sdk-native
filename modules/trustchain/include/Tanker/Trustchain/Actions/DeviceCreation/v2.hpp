#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation/v1.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
#define TANKER_TRUSTCHAIN_ACTIONS_DEVICE_CREATION_V2_ATTRIBUTES   \
  (lastReset, Crypto::Hash),                                      \
      (ephemeralPublicSignatureKey, Crypto::PublicSignatureKey),  \
      (userId, UserId), (delegationSignature, Crypto::Signature), \
      (publicSignatureKey, Crypto::PublicSignatureKey),           \
      (publicEncryptionKey, Crypto::PublicEncryptionKey)

class DeviceCreation2
{
public:
  TANKER_IMMUTABLE_DATA_TYPE_IMPLEMENTATION_2(
      DeviceCreation2, TANKER_TRUSTCHAIN_ACTIONS_DEVICE_CREATION_V2_ATTRIBUTES)

public:
  static constexpr Nature nature();

  DeviceCreation1 asDeviceCreation1() const;

private:
  friend void from_serialized(Serialization::SerializedSource&,
                              DeviceCreation2&);
};

constexpr Nature DeviceCreation2::nature()
{
  return Nature::DeviceCreation2;
}

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(DeviceCreation2)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(DeviceCreation2)
}
}
}
