#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation/v1.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Json.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Serialization.hpp>
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

  TANKER_IMMUTABLE_DATA_TYPE_IMPLEMENTATION_2(
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

  static constexpr Nature nature();

  std::vector<std::uint8_t> signatureData() const;
  Crypto::Signature const& sign(Crypto::PrivateSignatureKey const&);

private:
  friend void from_serialized(Serialization::SerializedSource&,
                              DeviceCreation3&);
};

constexpr Nature DeviceCreation3::nature()
{
  return Nature::DeviceCreation3;
}

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(DeviceCreation3)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(DeviceCreation3)
}
}
}
