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
#include <Tanker/Crypto/TwoTimesSealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/TwoTimesSealedSymmetricKey.hpp>

namespace Tanker
{
namespace Crypto
{
template class BasicCryptographicType<AeadIv, AeadIv::arraySize>;
template class BasicCryptographicType<BasicHash<void>, BasicHash<void>::arraySize>;
template class BasicHash<void>;
template class BasicCryptographicType<EncryptedSymmetricKey, EncryptedSymmetricKey::arraySize>;
template class BasicCryptographicType<Mac, Mac::arraySize>;
template class BasicCryptographicType<AsymmetricKey<KeyType::Private, KeyUsage::Encryption>,
                                      AsymmetricKey<KeyType::Private, KeyUsage::Encryption>::arraySize>;
template class AsymmetricKey<KeyType::Private, KeyUsage::Encryption>;
template class BasicCryptographicType<AsymmetricKey<KeyType::Private, KeyUsage::Signature>,
                                      AsymmetricKey<KeyType::Private, KeyUsage::Signature>::arraySize>;
template class AsymmetricKey<KeyType::Private, KeyUsage::Signature>;
template class BasicCryptographicType<AsymmetricKey<KeyType::Public, KeyUsage::Encryption>,
                                      AsymmetricKey<KeyType::Public, KeyUsage::Encryption>::arraySize>;
template class AsymmetricKey<KeyType::Public, KeyUsage::Encryption>;
template class BasicCryptographicType<AsymmetricKey<KeyType::Public, KeyUsage::Signature>,
                                      AsymmetricKey<KeyType::Public, KeyUsage::Signature>::arraySize>;
template class AsymmetricKey<KeyType::Public, KeyUsage::Signature>;
template class BasicCryptographicType<SealedPrivateEncryptionKey, SealedPrivateEncryptionKey::arraySize>;
template class BasicCryptographicType<SealedPrivateSignatureKey, SealedPrivateSignatureKey::arraySize>;
template class BasicCryptographicType<SealedSymmetricKey, SealedSymmetricKey::arraySize>;
template class BasicCryptographicType<TwoTimesSealedSymmetricKey, TwoTimesSealedSymmetricKey::arraySize>;
template class BasicCryptographicType<TwoTimesSealedPrivateEncryptionKey,
                                      TwoTimesSealedPrivateEncryptionKey::arraySize>;
template class BasicCryptographicType<Signature, Signature::arraySize>;
template class BasicCryptographicType<SymmetricKey, SymmetricKey::arraySize>;
}
}
