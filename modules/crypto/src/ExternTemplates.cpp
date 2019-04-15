#include <Tanker/Crypto/AeadIv.hpp>
#include <Tanker/Crypto/BasicHash.hpp>
#include <Tanker/Crypto/EncryptedSymmetricKey.hpp>
#include <Tanker/Crypto/Mac.hpp>
#include <Tanker/Crypto/PrivateEncryptionKey.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateSignatureKey.hpp>
#include <Tanker/Crypto/SealedSymmetricKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>

namespace Tanker
{
namespace Crypto
{
template class BasicCryptographicType<
    AeadIv,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>;
template class BasicCryptographicType<BasicHash<void>,
                                      crypto_generichash_BYTES>;
template class BasicHash<void>;
template class BasicCryptographicType<
    EncryptedSymmetricKey,
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES + crypto_box_MACBYTES +
        crypto_box_NONCEBYTES>;
template class BasicCryptographicType<
    Mac,
    crypto_aead_xchacha20poly1305_ietf_ABYTES>;
template class BasicCryptographicType<
    AsymmetricKey<KeyType::Private, KeyUsage::Encryption>,
    crypto_box_SECRETKEYBYTES>;
template class AsymmetricKey<KeyType::Private, KeyUsage::Encryption>;
template class BasicCryptographicType<
    AsymmetricKey<KeyType::Private, KeyUsage::Signature>,
    crypto_sign_SECRETKEYBYTES>;
template class AsymmetricKey<KeyType::Private, KeyUsage::Signature>;
template class BasicCryptographicType<
    AsymmetricKey<KeyType::Public, KeyUsage::Encryption>,
    crypto_box_PUBLICKEYBYTES>;
template class AsymmetricKey<KeyType::Public, KeyUsage::Encryption>;
template class BasicCryptographicType<
    AsymmetricKey<KeyType::Public, KeyUsage::Signature>,
    crypto_sign_PUBLICKEYBYTES>;
template class AsymmetricKey<KeyType::Public, KeyUsage::Signature>;
template class BasicCryptographicType<SealedPrivateEncryptionKey,
                                      crypto_box_SECRETKEYBYTES +
                                          crypto_box_SEALBYTES>;
template class BasicCryptographicType<SealedPrivateSignatureKey,
                                      crypto_sign_SECRETKEYBYTES +
                                          crypto_box_SEALBYTES>;
template class BasicCryptographicType<
    SealedSymmetricKey,
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES + crypto_box_SEALBYTES>;
template class BasicCryptographicType<Signature, crypto_sign_BYTES>;
template class BasicCryptographicType<
    SymmetricKey,
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES>;
}
}
