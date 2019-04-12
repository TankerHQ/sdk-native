#pragma once

#include <Tanker/Crypto/AeadIv.hpp>
#include <Tanker/Crypto/BasicHash.hpp>
#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Crypto/InvalidKeySize.hpp>
#include <Tanker/Crypto/Mac.hpp>
#include <Tanker/Crypto/PrivateEncryptionKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Crypto/Types.hpp>

#include <gsl-lite.hpp>
#include <sodium/crypto_box.h>

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <typeinfo>
#include <vector>

namespace Tanker
{
namespace Crypto
{
namespace detail
{
template <typename T, typename = void>
struct container_resizer;

template <typename T>
struct container_resizer<T, std::enable_if_t<IsCryptographicType<T>::value>>
{
  static T resize(typename T::size_type size)
  {
    using namespace std::string_literals;

    if (T::arraySize != size)
    {
      throw InvalidKeySize("invalid size for "s + typeid(T).name() +
                           " while preparing container: got " +
                           std::to_string(size) + ", expected " +
                           std::to_string(T::arraySize));
    }
    return {};
  }
};

template <>
struct container_resizer<std::vector<uint8_t>>
{
  using type = std::vector<uint8_t>;

  static type resize(type::size_type size)
  {
    return type(size);
  }
};

// avoid including sodium.h
void generichash_impl(gsl::span<uint8_t> hash, gsl::span<uint8_t const> data);

void asymDecryptImpl(gsl::span<uint8_t const> cipherData,
                     gsl::span<uint8_t> clearData,
                     PublicEncryptionKey const& senderKey,
                     PrivateEncryptionKey const& recipientKey);

void sealDecryptImpl(gsl::span<uint8_t const> cipherData,
                     gsl::span<uint8_t> clearData,
                     EncryptionKeyPair const& recipientKeyPair);

void asymEncryptImpl(gsl::span<uint8_t const> clearData,
                     gsl::span<uint8_t> cipherData,
                     PrivateEncryptionKey const& senderKey,
                     PublicEncryptionKey const& recipientKey);

void sealEncryptImpl(gsl::span<uint8_t const> clearData,
                     gsl::span<uint8_t> cipherData,
                     PublicEncryptionKey const& recipientKey);
}

class DecryptFailed : public std::exception
{
public:
  DecryptFailed(std::string const& msg) : _msg(msg)
  {
  }

  char const* what() const noexcept override
  {
    return _msg.c_str();
  }

private:
  std::string _msg;
};

/// |--iv--|--data--||--mac--|
/// |--iv--|--encryptedData--|
template <typename Byte>
struct AeadStruct
{
  gsl::span<Byte> iv;
  gsl::span<Byte> encryptedData;
  gsl::span<Byte> mac;
};

using ConstAeadSpans = AeadStruct<uint8_t const>;
using AeadSpans = AeadStruct<uint8_t>;

template <typename Byte>
auto makeAeadBuffer(gsl::span<Byte> aeadData)
{
  auto const iv = aeadData.first(Crypto::AeadIv::arraySize);
  auto const data = aeadData.subspan(Crypto::AeadIv::arraySize);
  auto const mac = aeadData.last(Crypto::Mac::arraySize);
  return AeadStruct<Byte>{iv, data, mac};
}

template <typename T = BasicHash<void>>
T generichash(gsl::span<uint8_t const> data)
{
  T hash;
  detail::generichash_impl(hash, data);
  return hash;
}

std::vector<uint8_t> generichash16(gsl::span<uint8_t const> data);
void randomFill(gsl::span<uint8_t> data);

Signature sign(gsl::span<uint8_t const> data,
               PrivateSignatureKey const& privateSignatureKey);
bool verify(gsl::span<uint8_t const> data,
            Signature const& signature,
            PublicSignatureKey const& publicSignatureKey);

EncryptionKeyPair makeEncryptionKeyPair();
EncryptionKeyPair makeEncryptionKeyPair(PrivateEncryptionKey);
SignatureKeyPair makeSignatureKeyPair();
SignatureKeyPair makeSignatureKeyPair(PrivateSignatureKey);

SymmetricKey makeSymmetricKey();
size_t encryptedSize(size_t const clearSize);
size_t encryptedSize(ConstAeadSpans const&);
size_t decryptedSize(size_t const encryptedSize);
size_t decryptedSize(ConstAeadSpans const&);
gsl::span<uint8_t const> extractMac(gsl::span<uint8_t const> encryptedData);
// returns the Mac
gsl::span<uint8_t const> encryptAead(SymmetricKey const& key,
                                     uint8_t const* iv,
                                     uint8_t* encryptedData,
                                     gsl::span<uint8_t const> clearData,
                                     gsl::span<uint8_t const> associatedData);

std::vector<uint8_t> encryptAead(SymmetricKey const& key,
                                 gsl::span<uint8_t const> clearData,
                                 gsl::span<uint8_t const> ad = {});

void decryptAead(SymmetricKey const& key,
                 uint8_t const* iv,
                 uint8_t* clearData,
                 gsl::span<uint8_t const> encryptedData,
                 gsl::span<uint8_t const> associatedData);

std::vector<uint8_t> decryptAead(SymmetricKey const& key,
                                 gsl::span<uint8_t const> data,
                                 gsl::span<uint8_t const> ad = {});

AeadIv deriveIv(AeadIv const& ivSeed, uint64_t const number);

template <typename OutputContainer = std::vector<uint8_t>>
OutputContainer asymEncrypt(gsl::span<uint8_t const> clearData,
                            PrivateEncryptionKey const& senderKey,
                            PublicEncryptionKey const& recipientKey)
{
  using ContainerResizer = detail::container_resizer<OutputContainer>;

  auto res = ContainerResizer::resize(clearData.size() + crypto_box_MACBYTES +
                                      crypto_box_NONCEBYTES);
  detail::asymEncryptImpl(clearData, res, senderKey, recipientKey);
  return res;
}

template <typename OutputContainer = std::vector<uint8_t>>
OutputContainer asymDecrypt(gsl::span<uint8_t const> cipherData,
                            PublicEncryptionKey const& senderKey,
                            PrivateEncryptionKey const& recipientKey)
{
  using ContainerResizer = detail::container_resizer<OutputContainer>;

  if (cipherData.size() < crypto_box_MACBYTES + crypto_box_NONCEBYTES)
    throw DecryptFailed("asymmetric encrypted buffer too small");

  auto res = ContainerResizer::resize(cipherData.size() - crypto_box_MACBYTES -
                                      crypto_box_NONCEBYTES);
  detail::asymDecryptImpl(cipherData, res, senderKey, recipientKey);
  return res;
}

template <typename OutputContainer = std::vector<uint8_t>>
OutputContainer sealEncrypt(gsl::span<uint8_t const> clearData,
                            PublicEncryptionKey const& recipientKey)
{
  using ContainerResizer = detail::container_resizer<OutputContainer>;

  // CIPHER + MAC + PUBLIC_KEY
  auto res = ContainerResizer::resize(clearData.size() + crypto_box_SEALBYTES);
  detail::sealEncryptImpl(clearData, res, recipientKey);
  return res;
}

template <typename OutputContainer = std::vector<uint8_t>>
OutputContainer sealDecrypt(gsl::span<uint8_t const> cipherData,
                            EncryptionKeyPair const& recipientKeyPair)
{
  using ContainerResizer = detail::container_resizer<OutputContainer>;

  if (cipherData.size() < crypto_box_SEALBYTES)
    throw DecryptFailed("sealed buffer too small");

  auto res = ContainerResizer::resize(cipherData.size() - crypto_box_SEALBYTES);
  detail::sealDecryptImpl(cipherData, res, recipientKeyPair);
  return res;
}
}
}
