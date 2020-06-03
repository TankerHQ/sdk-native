#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>
#include <Tanker/Crypto/PrivateEncryptionKey.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Json.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Serialization.hpp>
#include <Tanker/Trustchain/UserId.hpp>

// TODO remove it once Crypto::Sealed<> is added
#include <nlohmann/json_fwd.hpp>
#include <sodium/crypto_box.h>

#include <cstddef>
#include <cstdint>
#include <tuple>

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
  class SealedPrivateEncryptionKeys
    : public Crypto::BasicCryptographicType<
          SealedPrivateEncryptionKeys,
          2 * Crypto::PrivateEncryptionKey::arraySize + crypto_box_SEALBYTES>
  {
    using base_t::base_t;
  };

  TANKER_IMMUTABLE_DATA_TYPE_IMPLEMENTATION(
      ProvisionalIdentityClaim,
      TANKER_TRUSTCHAIN_ACTIONS_PROVISIONAL_IDENTITY_CLAIM_ATTRIBUTES)

public:
  static constexpr Nature nature();

  ProvisionalIdentityClaim(
      UserId const& userId,
      Crypto::PublicSignatureKey const& appSignaturePublicKey,
      Crypto::PublicSignatureKey const& tankerSignaturePublicKey,
      Crypto::PublicEncryptionKey const& userPublicEncryptionKey,
      SealedPrivateEncryptionKeys const& sealedPrivateEncryptionKeys);

  std::vector<std::uint8_t> signatureData(DeviceId const& authorId) const;

  Crypto::Signature const& signWithAppKey(Crypto::PrivateSignatureKey const&,
                                          DeviceId const&);
  Crypto::Signature const& signWithTankerKey(Crypto::PrivateSignatureKey const&,
                                             DeviceId const&);

private:
  friend void from_serialized(Serialization::SerializedSource&,
                              ProvisionalIdentityClaim&);
};

constexpr Nature ProvisionalIdentityClaim::nature()
{
  return Nature::ProvisionalIdentityClaim;
}

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(ProvisionalIdentityClaim)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(ProvisionalIdentityClaim)
}
}
}

namespace std
{
template <>
class tuple_size<::Tanker::Trustchain::Actions::ProvisionalIdentityClaim::
                     SealedPrivateEncryptionKeys>
  : public integral_constant<
        size_t,
        ::Tanker::Trustchain::Actions::ProvisionalIdentityClaim::
            SealedPrivateEncryptionKeys::arraySize>
{
};

template <size_t I>
class tuple_element<I,
                    ::Tanker::Trustchain::Actions::ProvisionalIdentityClaim::
                        SealedPrivateEncryptionKeys>
  : public tuple_element<
        I,
        ::Tanker::Trustchain::Actions::ProvisionalIdentityClaim::
            SealedPrivateEncryptionKeys::base_t>
{
};
}
