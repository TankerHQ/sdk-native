#pragma once

#include <Tanker/Crypto/PrivateEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedPrivateSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Groups/GroupEncryptedKey.hpp>
#include <Tanker/Index.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/DeviceId.hpp>

#include <gsl-lite.hpp>
#include <nlohmann/json_fwd.hpp>
#include <optional.hpp>
#include <sodium/crypto_box.h>

#include <cstddef>
#include <vector>

namespace Tanker
{
struct ProvisionalIdentityClaim
{
  class SealedPrivateEncryptionKeys
    : public Crypto::BasicCryptographicType<
          SealedPrivateEncryptionKeys,
          2 * Crypto::PrivateEncryptionKey::arraySize + crypto_box_SEALBYTES>
  {
    using base_t::base_t;
  };

  Trustchain::UserId userId;
  Crypto::PublicSignatureKey appSignaturePublicKey;
  Crypto::PublicSignatureKey tankerSignaturePublicKey;
  Crypto::Signature authorSignatureByAppKey;
  Crypto::Signature authorSignatureByTankerKey;
  Crypto::PublicEncryptionKey userPublicEncryptionKey;
  SealedPrivateEncryptionKeys encryptedPrivateKeys;

  Trustchain::Actions::Nature nature() const;
  std::vector<Index> makeIndexes() const;
  std::vector<uint8_t> signatureData(DeviceId const& authorId) const;
};

bool operator==(ProvisionalIdentityClaim const& l,
                ProvisionalIdentityClaim const& r);
bool operator!=(ProvisionalIdentityClaim const& l,
                ProvisionalIdentityClaim const& r);

ProvisionalIdentityClaim deserializeProvisionalIdentityClaim(
    gsl::span<uint8_t const> data);

std::uint8_t* to_serialized(std::uint8_t* it,
                            ProvisionalIdentityClaim const& dc);

std::size_t serialized_size(ProvisionalIdentityClaim const& dc);

void to_json(nlohmann::json& j, ProvisionalIdentityClaim const& dc);
}

namespace std
{
template <>
class tuple_size<
    ::Tanker::ProvisionalIdentityClaim::SealedPrivateEncryptionKeys>
  : public integral_constant<size_t,
                             ::Tanker::ProvisionalIdentityClaim::
                                 SealedPrivateEncryptionKeys::arraySize>
{
};

template <size_t I>
class tuple_element<
    I,
    ::Tanker::ProvisionalIdentityClaim::SealedPrivateEncryptionKeys>
  : public tuple_element<
        I,
        ::Tanker::ProvisionalIdentityClaim::SealedPrivateEncryptionKeys::base_t>
{
};
}
