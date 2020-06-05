#pragma once

#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
#define TANKER_TRUSTCHAIN_ACTIONS_DEVICE_CREATION_V3_ATTRIBUTES                \
  (ephemeralPublicSignatureKey, Crypto::PublicSignatureKey), (userId, UserId), \
      (delegationSignature, Crypto::Signature),                                \
      (publicSignatureKey, Crypto::PublicSignatureKey),                        \
      (publicEncryptionKey, Crypto::PublicEncryptionKey),                      \
      (publicUserEncryptionKey, Crypto::PublicEncryptionKey),                  \
      (sealedPrivateUserEncryptionKey, Crypto::SealedPrivateEncryptionKey),    \
      (isGhostDevice, bool)

class DeviceCreation3
{
public:
  enum class DeviceType
  {
    Device,
    GhostDevice,
  };

  TANKER_IMMUTABLE_ACTION_IMPLEMENTATION(
      DeviceCreation3, TANKER_TRUSTCHAIN_ACTIONS_DEVICE_CREATION_V3_ATTRIBUTES)

public:
  DeviceCreation3(
      TrustchainId const& trustchainId,
      Crypto::PublicSignatureKey const& ephemeralPublicSignatureKey,
      UserId const& userId,
      Crypto::Signature const& delegationSignature,
      Crypto::PublicSignatureKey const& publicSignatureKey,
      Crypto::PublicEncryptionKey const& publicEncryptionKey,
      Crypto::PublicEncryptionKey const& publicUserEncryptionKey,
      Crypto::SealedPrivateEncryptionKey const& sealedPrivateEncryptionKey,
      bool isGhostDevice,
      Crypto::Hash const& author,
      Crypto::PrivateSignatureKey const& delegationPrivateSignatureKey);

  std::vector<std::uint8_t> delegationSignatureData() const;

private:
  friend void from_serialized(Serialization::SerializedSource&,
                              DeviceCreation3&);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(DeviceCreation3)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(DeviceCreation3)
}
}
}
