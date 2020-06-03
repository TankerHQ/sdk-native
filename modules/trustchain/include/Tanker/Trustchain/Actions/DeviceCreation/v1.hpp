#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Json.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Serialization.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
#define TANKER_TRUSTCHAIN_ACTIONS_DEVICE_CREATION_V1_ATTRIBUTES                \
  (ephemeralPublicSignatureKey, Crypto::PublicSignatureKey), (userId, UserId), \
      (delegationSignature, Crypto::Signature),                                \
      (publicSignatureKey, Crypto::PublicSignatureKey),                        \
      (publicEncryptionKey, Crypto::PublicEncryptionKey)

class DeviceCreation1
{
public:
  TANKER_IMMUTABLE_DATA_TYPE_IMPLEMENTATION_2(
      DeviceCreation1, TANKER_TRUSTCHAIN_ACTIONS_DEVICE_CREATION_V1_ATTRIBUTES)

public:
  DeviceCreation1(
      TrustchainId const& trustchainId,
      Crypto::PublicSignatureKey const& ephemeralPublicSignatureKey,
      UserId const& userId,
      Crypto::Signature const& delegationSignature,
      Crypto::PublicSignatureKey const& publicSignatureKey,
      Crypto::PublicEncryptionKey const& publicEncryptionKey,
      Crypto::Hash const& author,
      Crypto::PrivateSignatureKey const& delegationPrivateSignatureKey);

  static constexpr Nature nature();

  std::vector<std::uint8_t> signatureData() const;

protected:
  friend void from_serialized(Serialization::SerializedSource&,
                              DeviceCreation1&);
};

constexpr Nature DeviceCreation1::nature()
{
  return Nature::DeviceCreation;
}

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(DeviceCreation1)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(DeviceCreation1)
}
}
}
