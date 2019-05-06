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
#include <Tanker/Trustchain/UserId.hpp>

// TODO remove it once Crypto::Sealed<> is added
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

  static constexpr Nature nature();

  ProvisionalIdentityClaim() = default;
  ProvisionalIdentityClaim(
      UserId const& userId,
      Crypto::PublicSignatureKey const& appSignaturePublicKey,
      Crypto::Signature const& authorSignatureByAppKey,
      Crypto::PublicSignatureKey const& tankerSignaturePublicKey,
      Crypto::Signature const& authorSignatureByTankerKey,
      Crypto::PublicEncryptionKey const& userPublicEncryptionKey,
      SealedPrivateEncryptionKeys const& sealedPrivateEncryptionKeys);
  ProvisionalIdentityClaim(
      UserId const& userId,
      Crypto::PublicSignatureKey const& appSignaturePublicKey,
      Crypto::PublicSignatureKey const& tankerSignaturePublicKey,
      Crypto::PublicEncryptionKey const& userPublicEncryptionKey,
      SealedPrivateEncryptionKeys const& sealedPrivateEncryptionKeys);

  UserId const& userId() const;
  Crypto::PublicSignatureKey const& appSignaturePublicKey() const;
  Crypto::PublicSignatureKey const& tankerSignaturePublicKey() const;
  Crypto::Signature const& authorSignatureByAppKey() const;
  Crypto::Signature const& authorSignatureByTankerKey() const;
  Crypto::PublicEncryptionKey const& userPublicEncryptionKey() const;
  SealedPrivateEncryptionKeys const& sealedPrivateEncryptionKeys() const;

  std::vector<std::uint8_t> signatureData(DeviceId const& authorId) const;

  Crypto::Signature const& signWithAppKey(Crypto::PrivateSignatureKey const&,
                                          DeviceId const&);
  Crypto::Signature const& signWithTankerKey(Crypto::PrivateSignatureKey const&,
                                             DeviceId const&);

private:
  UserId _userId;
  Crypto::PublicSignatureKey _appSignaturePublicKey;
  Crypto::PublicSignatureKey _tankerSignaturePublicKey;
  Crypto::Signature _authorSignatureByAppKey;
  Crypto::Signature _authorSignatureByTankerKey;
  Crypto::PublicEncryptionKey _userPublicEncryptionKey;
  SealedPrivateEncryptionKeys _sealedPrivateEncryptionKeys;

  friend void from_serialized(Serialization::SerializedSource&,
                              ProvisionalIdentityClaim&);
};

bool operator==(ProvisionalIdentityClaim const& lhs,
                ProvisionalIdentityClaim const& rhs);

bool operator!=(ProvisionalIdentityClaim const& lhs,
                ProvisionalIdentityClaim const& rhs);

constexpr Nature ProvisionalIdentityClaim::nature()
{
  return Nature::ProvisionalIdentityClaim;
}
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

#include <Tanker/Trustchain/Json/ProvisionalIdentityClaim.hpp>
#include <Tanker/Trustchain/Serialization/ProvisionalIdentityClaim.hpp>
