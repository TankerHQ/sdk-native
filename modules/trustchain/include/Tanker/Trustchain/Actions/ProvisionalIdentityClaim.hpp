#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>
#include <Tanker/Crypto/PrivateEncryptionKey.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <sodium/crypto_box.h>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
#define TANKER_TRUSTCHAIN_ACTIONS_PROVISIONAL_IDENTITY_CLAIM_ATTRIBUTES  \
  (userId, UserId), (appSignaturePublicKey, Crypto::PublicSignatureKey), \
      (tankerSignaturePublicKey, Crypto::PublicSignatureKey),            \
      (authorSignatureByAppKey, Crypto::Signature),                      \
      (authorSignatureByTankerKey, Crypto::Signature),                   \
      (userPublicEncryptionKey, Crypto::PublicEncryptionKey),            \
      (sealedPrivateEncryptionKeys, SealedPrivateEncryptionKeys)

class ProvisionalIdentityClaim
{
public:
  // cannot be refactored using Sealed, keep this ad-hoc class
  class SealedPrivateEncryptionKeys
    : public Crypto::BasicCryptographicType<
          SealedPrivateEncryptionKeys,
          2 * Crypto::PrivateEncryptionKey::arraySize + crypto_box_SEALBYTES>
  {
    using base_t::base_t;
  };

  TANKER_IMMUTABLE_ACTION_IMPLEMENTATION(
      ProvisionalIdentityClaim,
      TANKER_TRUSTCHAIN_ACTIONS_PROVISIONAL_IDENTITY_CLAIM_ATTRIBUTES)

public:
  ProvisionalIdentityClaim(
      TrustchainId const& trustchainId,
      UserId const& userId,
      Crypto::SignatureKeyPair const& appSignatureKeyPair,
      Crypto::SignatureKeyPair const& tankerSignatureKeyPair,
      Crypto::PublicEncryptionKey const& userPublicEncryptionKey,
      SealedPrivateEncryptionKeys const& sealedPrivateEncryptionKeys,
      DeviceId const& author,
      Crypto::PrivateSignatureKey const& devicePrivateSignatureKey);

  std::vector<std::uint8_t> signatureData(DeviceId const& authorId) const;

private:
  friend void from_serialized(Serialization::SerializedSource&,
                              ProvisionalIdentityClaim&);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(ProvisionalIdentityClaim)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(ProvisionalIdentityClaim)
}
}
}
