#include <Tanker/Crypto/Crypto.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Exception.hpp>

#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_generichash.h>
#include <sodium/crypto_scalarmult.h>
#include <sodium/crypto_sign.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/randombytes.h>

#include <cassert>
#include <cstddef>
#include <cstdint>

using Tanker::Errors::Exception;

namespace Tanker
{
namespace Crypto
{
namespace detail
{
void generichash_impl(gsl::span<uint8_t> hash, gsl::span<uint8_t const> data)
{
  crypto_generichash(hash.data(), hash.size(), data.data(), data.size(), nullptr, 0);
}

void asymDecryptImpl(gsl::span<uint8_t const> cipherData,
                     gsl::span<uint8_t> clearData,
                     PublicEncryptionKey const& senderKey,
                     PrivateEncryptionKey const& recipientKey)
{
  assert(clearData.size() == cipherData.size() - crypto_box_MACBYTES - crypto_box_NONCEBYTES);

  auto const nonce = cipherData.subspan(cipherData.size() - crypto_box_NONCEBYTES, crypto_box_NONCEBYTES);
  auto const error = crypto_box_open_easy(clearData.data(),
                                          cipherData.data(),
                                          cipherData.size() - crypto_box_NONCEBYTES,
                                          nonce.data(),
                                          senderKey.data(),
                                          recipientKey.data());
  if (error != 0)
    throw Exception(Errc::AsymmetricDecryptionFailed);
}

void sealDecryptImpl(gsl::span<uint8_t const> cipherData,
                     gsl::span<uint8_t> clearData,
                     EncryptionKeyPair const& recipientKeyPair)
{
  assert(cipherData.size() >= crypto_box_SEALBYTES);
  auto const error = crypto_box_seal_open(clearData.data(),
                                          cipherData.data(),
                                          cipherData.size(),
                                          recipientKeyPair.publicKey.data(),
                                          recipientKeyPair.privateKey.data());
  if (error != 0)
    throw Exception(Errc::SealedDecryptionFailed);
}

void asymEncryptImpl(gsl::span<uint8_t const> clearData,
                     gsl::span<uint8_t> cipherData,
                     PrivateEncryptionKey const& senderKey,
                     PublicEncryptionKey const& recipientKey)
{
  assert(cipherData.size() == clearData.size() + crypto_box_MACBYTES + crypto_box_NONCEBYTES);

  auto nonce = cipherData.subspan(clearData.size() + crypto_box_MACBYTES, crypto_box_NONCEBYTES);
  randomFill(nonce);
  auto const error = crypto_box_easy(
      cipherData.data(), clearData.data(), clearData.size(), nonce.data(), recipientKey.data(), senderKey.data());
  if (error != 0)
    throw Exception(Errc::AsymmetricEncryptionFailed);
}

void sealEncryptImpl(gsl::span<uint8_t const> clearData,
                     gsl::span<uint8_t> cipherData,
                     PublicEncryptionKey const& recipientKey)
{
  assert(cipherData.size() == clearData.size() + crypto_box_SEALBYTES);
  auto const error = crypto_box_seal(cipherData.data(), clearData.data(), clearData.size(), recipientKey.data());
  if (error != 0)
    throw Exception(Errc::SealedEncryptionFailed);
}
}

std::vector<uint8_t> generichash16(gsl::span<uint8_t const> data)
{
  std::vector<uint8_t> hash(crypto_generichash_BYTES_MIN);
  crypto_generichash(hash.data(), hash.size(), data.data(), data.size(), nullptr, 0);
  return hash;
}

void randomFill(gsl::span<uint8_t> data)
{
  randombytes_buf(data.data(), data.size());
}

Signature sign(gsl::span<uint8_t const> data, PrivateSignatureKey const& privateSignatureKey)
{
  Signature signature;
  crypto_sign_detached(signature.data(), NULL, data.data(), data.size(), privateSignatureKey.data());
  return signature;
}

bool verify(gsl::span<uint8_t const> data, Signature const& signature, PublicSignatureKey const& publicSignatureKey)
{
  return crypto_sign_verify_detached(signature.data(), data.data(), data.size(), publicSignatureKey.data()) == 0;
}

EncryptionKeyPair makeEncryptionKeyPair()
{
  EncryptionKeyPair p;
  crypto_box_keypair(p.publicKey.data(), p.privateKey.data());
  return p;
}

EncryptionKeyPair makeEncryptionKeyPair(PrivateEncryptionKey const& privateKey)
{
  return {derivePublicKey(privateKey), privateKey};
}

SignatureKeyPair makeSignatureKeyPair()
{
  SignatureKeyPair p;
  crypto_sign_keypair(p.publicKey.data(), p.privateKey.data());
  return p;
}

SignatureKeyPair makeSignatureKeyPair(PrivateSignatureKey const& privateKey)
{
  return {derivePublicKey(privateKey), privateKey};
}

SymmetricKey makeSymmetricKey()
{
  SymmetricKey key;
  randombytes_buf(key.data(), key.size());
  return key;
}

PublicEncryptionKey derivePublicKey(PrivateEncryptionKey const& privateKey)
{
  PublicEncryptionKey publicKey;

  crypto_scalarmult_base(publicKey.data(), privateKey.data());
  return publicKey;
}

PublicSignatureKey derivePublicKey(PrivateSignatureKey const& privateKey)
{
  PublicSignatureKey publicKey;

  crypto_sign_ed25519_sk_to_pk(publicKey.data(), privateKey.data());
  return publicKey;
}

static constexpr auto aeadOverhead = crypto_aead_xchacha20poly1305_ietf_ABYTES;

size_t encryptedSize(size_t const clearSize)
{
  return clearSize + aeadOverhead;
}

size_t decryptedSize(size_t const encryptedSize)
{
  if (encryptedSize < aeadOverhead)
    throw Exception(Errc::InvalidEncryptedDataSize);
  return encryptedSize - aeadOverhead;
}

gsl::span<uint8_t const> extractMac(gsl::span<uint8_t const> encryptedData)
{
  try
  {
    return encryptedData.subspan(encryptedData.size() - aeadOverhead, crypto_aead_xchacha20poly1305_ietf_ABYTES);
  }
  catch (gsl::fail_fast const&)
  {
    throw Exception(Errc::InvalidEncryptedDataSize);
  }
}

gsl::span<uint8_t const> encryptAead(SymmetricKey const& key,
                                     gsl::span<uint8_t const> iv,
                                     gsl::span<uint8_t> encryptedData,
                                     gsl::span<uint8_t const> clearData,
                                     gsl::span<uint8_t const> associatedData)
{
  if (encryptedData.size() < clearData.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES)
    throw Errors::AssertionError("encryptAead: encryptedData buffer is too short");
  if (iv.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    throw Errors::AssertionError("encryptAead: iv buffer is of the wrong size");

  crypto_aead_xchacha20poly1305_ietf_encrypt(encryptedData.data(),
                                             nullptr,
                                             clearData.data(),
                                             clearData.size(),
                                             associatedData.data(),
                                             associatedData.size(),
                                             nullptr,
                                             iv.data(),
                                             key.data());

  return encryptedData.subspan(clearData.size());
}

std::size_t encryptedSize(ConstAeadSpans const& aead)
{
  return aead.encryptedData.size();
}

std::size_t decryptedSize(ConstAeadSpans const& aead)
{
  return aead.encryptedData.size() - aead.mac.size();
}

std::vector<uint8_t> encryptAead(SymmetricKey const& key,
                                 gsl::span<uint8_t const> clearData,
                                 gsl::span<uint8_t const> ad)
{
  auto ptr = std::vector<uint8_t>(Crypto::AeadIv::arraySize + clearData.size() + Crypto::Mac::arraySize);
  auto aeadBuffer = makeAeadBuffer<uint8_t>(ptr);
  Crypto::randomFill(aeadBuffer.iv);
  encryptAead(key, aeadBuffer.iv, aeadBuffer.encryptedData, clearData, ad);
  return ptr;
}

void decryptAead(SymmetricKey const& key,
                 gsl::span<uint8_t const> iv,
                 gsl::span<uint8_t> clearData,
                 gsl::span<uint8_t const> encryptedData,
                 gsl::span<uint8_t const> associatedData)
{
  if (clearData.size() < encryptedData.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES)
    throw Errors::AssertionError("decryptAead: clearData buffer is too short");
  if (iv.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    throw Errors::AssertionError("decryptAead: iv buffer is of the wrong size");

  auto const error = crypto_aead_xchacha20poly1305_ietf_decrypt(clearData.data(),
                                                                nullptr,
                                                                nullptr,
                                                                encryptedData.data(),
                                                                encryptedData.size(),
                                                                associatedData.data(),
                                                                associatedData.size(),
                                                                iv.data(),
                                                                key.data());
  if (error != 0)
    throw Exception(Errc::AeadDecryptionFailed, "MAC verification failed");
}

std::vector<uint8_t> decryptAead(SymmetricKey const& key,
                                 gsl::span<uint8_t const> aeadData,
                                 gsl::span<uint8_t const> ad)
{
  auto const aeadBuffer = makeAeadBuffer(aeadData);
  std::vector<uint8_t> res(decryptedSize(aeadBuffer));
  decryptAead(key, aeadBuffer.iv, res, aeadBuffer.encryptedData, ad);
  return res;
}

void tryDecryptAead(std::optional<Crypto::SymmetricKey> const& key,
                    ResourceId const& resourceId,
                    gsl::span<uint8_t const> iv,
                    gsl::span<uint8_t> clearData,
                    gsl::span<uint8_t const> encryptedData,
                    gsl::span<uint8_t const> associatedData)
{
  if (!key)
  {
    throw formatEx(Errors::Errc::InvalidArgument, "key not found for resource: {:s}", resourceId);
  }
  return decryptAead(*key, iv, clearData, encryptedData, associatedData);
}

void tryDecryptAead(std::optional<Crypto::SymmetricKey> const& key,
                    SimpleResourceId const& resourceId,
                    gsl::span<uint8_t const> iv,
                    gsl::span<uint8_t> clearData,
                    gsl::span<uint8_t const> encryptedData,
                    gsl::span<uint8_t const> associatedData)
{
  return tryDecryptAead(key, ResourceId{resourceId}, iv, clearData, encryptedData, associatedData);
}

void tryDecryptAead(std::optional<Crypto::SymmetricKey> const& key,
                    CompositeResourceId const& resourceId,
                    gsl::span<uint8_t const> iv,
                    gsl::span<uint8_t> clearData,
                    gsl::span<uint8_t const> encryptedData,
                    gsl::span<uint8_t const> associatedData)
{
  return tryDecryptAead(key, ResourceId{resourceId}, iv, clearData, encryptedData, associatedData);
}

Hash prehashPassword(std::string password)
{
  if (password.empty())
    throw Errors::formatEx(Errc::InvalidBufferSize, "cannot hash an empty password");

  static constexpr char PASSWORD_PEPPER[] = "2NsxLuBPL7JanD2SIjb9erBgVHjMFh";

  password += PASSWORD_PEPPER;
  return generichash(gsl::span(reinterpret_cast<uint8_t const*>(password.data()), password.size()));
}
}
}
