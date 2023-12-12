#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation/v1.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
#define TANKER_TRUSTCHAIN_ACTIONS_DEVICE_CREATION_V2_ATTRIBUTES                                           \
  (lastReset, Crypto::Hash), (ephemeralPublicSignatureKey, Crypto::PublicSignatureKey), (userId, UserId), \
      (delegationSignature, Crypto::Signature), (publicSignatureKey, Crypto::PublicSignatureKey),         \
      (publicEncryptionKey, Crypto::PublicEncryptionKey)

class DeviceCreation2
{
public:
  TANKER_IMMUTABLE_ACTION_IMPLEMENTATION(DeviceCreation2, TANKER_TRUSTCHAIN_ACTIONS_DEVICE_CREATION_V2_ATTRIBUTES)

public:
  DeviceCreation1 asDeviceCreation1() const;

private:
  friend void from_serialized(Serialization::SerializedSource&, DeviceCreation2&);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(DeviceCreation2)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(DeviceCreation2)
}
}
}
