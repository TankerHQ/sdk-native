#pragma once

#include <Tanker/Crypto/AsymmetricKey.hpp>
#include <Tanker/Crypto/InvalidKeySize.hpp>
#include <Tanker/Crypto/IsCryptographicType.hpp>
#include <Tanker/Crypto/KeyType.hpp>
#include <Tanker/Crypto/KeyUsage.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PrivateEncryptionKey.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>

#include <Tanker/Crypto/detail/ArrayHelpers.hpp>
#include <Tanker/Crypto/detail/CryptographicType.hpp>
#include <Tanker/Crypto/detail/CryptographicTypeImpl.hpp>
#include <Tanker/Crypto/detail/IsCryptographicType.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <gsl-lite.hpp>
#include <nlohmann/json_fwd.hpp>
#include <sodium.h>

#include <tuple>
#include <utility>

namespace Tanker
{
namespace Crypto
{
template <KeyUsage Usage>
struct KeyPair
{
  AsymmetricKey<KeyType::Public, Usage> publicKey;
  AsymmetricKey<KeyType::Private, Usage> privateKey;
};

template <KeyUsage Usage>
bool operator==(KeyPair<Usage> const& a, KeyPair<Usage> const& b)
{
  return std::tie(a.publicKey, a.privateKey) ==
         std::tie(b.publicKey, b.privateKey);
}

template <KeyUsage Usage>
bool operator!=(KeyPair<Usage> const& a, KeyPair<Usage> const& b)
{
  return !(a == b);
}

using SignatureKeyPair = KeyPair<KeyUsage::Signature>;
using EncryptionKeyPair = KeyPair<KeyUsage::Encryption>;

template <typename>
class BasicHash : std::array<uint8_t, crypto_generichash_BYTES>
{
  TANKER_CRYPTO_CRYPTOGRAPHIC_TYPE_IMPL(BasicHash,
                                        crypto_generichash_BYTES,
                                        BasicHash)
};

using Hash = BasicHash<void>;

template <typename T>
bool operator==(BasicHash<void> const& lhs, BasicHash<T> const& rhs) noexcept
{
  return lhs.base() == rhs.base();
}

template <typename T>
bool operator==(BasicHash<T> const& lhs, BasicHash<void> const& rhs) noexcept
{
  return rhs == lhs;
}

template <typename T>
bool operator!=(BasicHash<void> const& lhs, BasicHash<T> const& rhs) noexcept
{
  return !(lhs == rhs);
}

template <typename T>
bool operator!=(BasicHash<T> const& lhs, BasicHash<void> const& rhs) noexcept
{
  return !(lhs == rhs);
}

TANKER_CRYPTO_CRYPTOGRAPHIC_TYPE(Signature, crypto_sign_BYTES)
TANKER_CRYPTO_CRYPTOGRAPHIC_TYPE(Mac, crypto_aead_xchacha20poly1305_ietf_ABYTES)
TANKER_CRYPTO_CRYPTOGRAPHIC_TYPE(SymmetricKey,
                                 crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
TANKER_CRYPTO_CRYPTOGRAPHIC_TYPE(AeadIv,
                                 crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
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

template <typename T>
struct IsCryptographicType<BasicHash<T>> : std::true_type
{
};

TANKER_CRYPTO_IS_CRYPTOGRAPHIC_TYPE(Signature)
TANKER_CRYPTO_IS_CRYPTOGRAPHIC_TYPE(Mac)
TANKER_CRYPTO_IS_CRYPTOGRAPHIC_TYPE(SymmetricKey)
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
TANKER_CRYPTO_STD_TUPLE_SIZE_ELEMENT_TPL_ARG(::Tanker::Crypto::BasicHash)
TANKER_CRYPTO_STD_TUPLE_SIZE_ELEMENT(::Tanker::Crypto::Mac)
TANKER_CRYPTO_STD_TUPLE_SIZE_ELEMENT(::Tanker::Crypto::Signature)
TANKER_CRYPTO_STD_TUPLE_SIZE_ELEMENT(::Tanker::Crypto::SymmetricKey)
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
