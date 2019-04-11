#pragma once

#include <Tanker/Crypto/AeadIv.hpp>
#include <Tanker/Crypto/AsymmetricKey.hpp>
#include <Tanker/Crypto/BasicHash.hpp>
#include <Tanker/Crypto/EncryptedSymmetricKey.hpp>
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
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateSignatureKey.hpp>
#include <Tanker/Crypto/SealedSymmetricKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>

#include <Tanker/Crypto/Serialization/Serialization.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <gsl-lite.hpp>
#include <nlohmann/json_fwd.hpp>
#include <sodium.h>

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
