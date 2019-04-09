#pragma once

#include <Tanker/Crypto/AeadIv.hpp>
#include <Tanker/Crypto/AsymmetricKey.hpp>
#include <Tanker/Crypto/BasicHash.hpp>
#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/InvalidKeySize.hpp>
#include <Tanker/Crypto/IsCryptographicType.hpp>
#include <Tanker/Crypto/KeyPair.hpp>
#include <Tanker/Crypto/KeyType.hpp>
#include <Tanker/Crypto/KeyUsage.hpp>
#include <Tanker/Crypto/Mac.hpp>
#include <Tanker/Crypto/PrivateEncryptionKey.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>

#include <Tanker/Crypto/detail/ArrayHelpers.hpp>
#include <Tanker/Crypto/detail/CryptographicType.hpp>
#include <Tanker/Crypto/detail/CryptographicTypeImpl.hpp>
#include <Tanker/Crypto/detail/IsCryptographicType.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <gsl-lite.hpp>
#include <nlohmann/json_fwd.hpp>
#include <sodium.h>

namespace Tanker
{
namespace Crypto
{
TANKER_CRYPTO_CRYPTOGRAPHIC_TYPE(SealedPrivateEncryptionKey,
                                 crypto_box_SECRETKEYBYTES +
                                     crypto_box_SEALBYTES)
TANKER_CRYPTO_CRYPTOGRAPHIC_TYPE(SealedPrivateSignatureKey,
                                 crypto_sign_SECRETKEYBYTES +
                                     crypto_box_SEALBYTES)
TANKER_CRYPTO_CRYPTOGRAPHIC_TYPE(EncryptedSymmetricKey,
                                 crypto_aead_xchacha20poly1305_ietf_KEYBYTES +
                                     crypto_box_MACBYTES +
                                     crypto_box_NONCEBYTES)
TANKER_CRYPTO_CRYPTOGRAPHIC_TYPE(SealedSymmetricKey,
                                 crypto_aead_xchacha20poly1305_ietf_KEYBYTES +
                                     crypto_box_SEALBYTES)

TANKER_CRYPTO_IS_CRYPTOGRAPHIC_TYPE(SealedPrivateEncryptionKey)
TANKER_CRYPTO_IS_CRYPTOGRAPHIC_TYPE(SealedPrivateSignatureKey)
TANKER_CRYPTO_IS_CRYPTOGRAPHIC_TYPE(EncryptedSymmetricKey)
TANKER_CRYPTO_IS_CRYPTOGRAPHIC_TYPE(SealedSymmetricKey)

template <typename T,
          typename = std::enable_if_t<IsCryptographicType<T>::value>>
constexpr std::size_t serialized_size(T const& val)
{
  return val.arraySize;
}

template <typename T,
          typename = std::enable_if_t<IsCryptographicType<T>::value>>
void from_serialized(Serialization::SerializedSource& ss, T& val)
{
  auto sp = ss.read(val.size());
  std::copy(sp.begin(), sp.end(), val.begin());
}

template <typename T,
          typename = std::enable_if_t<IsCryptographicType<T>::value>>
std::uint8_t* to_serialized(std::uint8_t* it, T const& val)
{
  return std::copy(val.begin(), val.end(), it);
}
}
}

namespace std
{
TANKER_CRYPTO_STD_TUPLE_SIZE_ELEMENT(
    ::Tanker::Crypto::SealedPrivateEncryptionKey)
TANKER_CRYPTO_STD_TUPLE_SIZE_ELEMENT(
    ::Tanker::Crypto::SealedPrivateSignatureKey)
TANKER_CRYPTO_STD_TUPLE_SIZE_ELEMENT(::Tanker::Crypto::EncryptedSymmetricKey)
TANKER_CRYPTO_STD_TUPLE_SIZE_ELEMENT(::Tanker::Crypto::SealedSymmetricKey)
}

namespace nlohmann
{
template <typename CryptoType>
struct adl_serializer<
    CryptoType,
    std::enable_if_t<Tanker::Crypto::IsCryptographicType<CryptoType>::value>>
{
  template <typename BasicJsonType>
  static void to_json(BasicJsonType& j, CryptoType const& value)
  {
    j = cppcodec::base64_rfc4648::encode(value);
  }

  template <typename BasicJsonType>
  static void from_json(BasicJsonType const& j, CryptoType& value)
  {
    value = cppcodec::base64_rfc4648::decode<CryptoType>(
        j.template get<std::string>());
  }
};
}
