#pragma once

#include <Tanker/Crypto/AeadIv.hpp>
#include <Tanker/Crypto/BasicHash.hpp>
#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Crypto/Errors/Errc.hpp>
#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/Mac.hpp>
#include <Tanker/Crypto/PrivateEncryptionKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/ResourceId.hpp>
#include <Tanker/Crypto/Sealed.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Errors/Exception.hpp>

#include <gsl/gsl-lite.hpp>
#include <sodium/crypto_box.h>

#include <cstddef>
#include <cstdint>
#include <optional>
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
    auto const containerSize = T::arraySize;

    if (containerSize != size)
    {
      throw Errors::formatEx(Errc::InvalidBufferSize,
                             FMT_STRING("invalid size for {:s} while preparing "
                                        "buffer: got {:d}, expected {:d}"),
                             typeid(T).name(),
                             size,
                             containerSize);
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

template <typename T = BasicHash<void>>
T generichash(std::string_view data)
{
  T hash;
  auto span = gsl::span(reinterpret_cast<uint8_t const*>(data.data()), data.size());
  detail::generichash_impl(hash, span);
  return hash;
}

std::vector<uint8_t> generichash16(gsl::span<uint8_t const> data);
void randomFill(gsl::span<uint8_t> data);

template <typename T, typename = std::enable_if_t<IsCryptographicType<T>::value>>
T getRandom()
{
  T ret;
  randomFill(ret);
  return ret;
}

Signature sign(gsl::span<uint8_t const> data, PrivateSignatureKey const& privateSignatureKey);
bool verify(gsl::span<uint8_t const> data, Signature const& signature, PublicSignatureKey const& publicSignatureKey);

EncryptionKeyPair makeEncryptionKeyPair();
EncryptionKeyPair makeEncryptionKeyPair(PrivateEncryptionKey const&);
SignatureKeyPair makeSignatureKeyPair();
SignatureKeyPair makeSignatureKeyPair(PrivateSignatureKey const&);

PublicEncryptionKey derivePublicKey(PrivateEncryptionKey const&);
PublicSignatureKey derivePublicKey(PrivateSignatureKey const&);

SymmetricKey makeSymmetricKey();
size_t encryptedSize(size_t const clearSize);
size_t encryptedSize(ConstAeadSpans const&);
size_t decryptedSize(size_t const encryptedSize);
size_t decryptedSize(ConstAeadSpans const&);
gsl::span<uint8_t const> extractMac(gsl::span<uint8_t const> encryptedData);
// returns the Mac
gsl::span<uint8_t const> encryptAead(SymmetricKey const& key,
                                     gsl::span<uint8_t const> iv,
                                     gsl::span<uint8_t> encryptedData,
                                     gsl::span<uint8_t const> clearData,
                                     gsl::span<uint8_t const> associatedData);

std::vector<uint8_t> encryptAead(SymmetricKey const& key,
                                 gsl::span<uint8_t const> clearData,
                                 gsl::span<uint8_t const> ad = {});

void decryptAead(SymmetricKey const& key,
                 gsl::span<uint8_t const> iv,
                 gsl::span<uint8_t> clearData,
                 gsl::span<uint8_t const> encryptedData,
                 gsl::span<uint8_t const> associatedData);

std::vector<uint8_t> decryptAead(SymmetricKey const& key,
                                 gsl::span<uint8_t const> data,
                                 gsl::span<uint8_t const> ad = {});

void tryDecryptAead(std::optional<Crypto::SymmetricKey> const& key,
                    ResourceId const& resourceId,
                    gsl::span<uint8_t const> iv,
                    gsl::span<uint8_t> clearData,
                    gsl::span<uint8_t const> encryptedData,
                    gsl::span<uint8_t const> associatedData);

void tryDecryptAead(std::optional<Crypto::SymmetricKey> const& key,
                    SimpleResourceId const& resourceId,
                    gsl::span<uint8_t const> iv,
                    gsl::span<uint8_t> clearData,
                    gsl::span<uint8_t const> encryptedData,
                    gsl::span<uint8_t const> associatedData);

void tryDecryptAead(std::optional<Crypto::SymmetricKey> const& key,
                    CompositeResourceId const& resourceId,
                    gsl::span<uint8_t const> iv,
                    gsl::span<uint8_t> clearData,
                    gsl::span<uint8_t const> encryptedData,
                    gsl::span<uint8_t const> associatedData);

template <typename SeedType>
AeadIv deriveIv(SeedType const& ivSeed, uint64_t const number)
{
  auto pointer = reinterpret_cast<uint8_t const*>(&number);
  auto const numberSize = sizeof(number);

  std::vector<uint8_t> toHash;
  toHash.reserve(numberSize + SeedType::arraySize);
  toHash.insert(toHash.end(), ivSeed.begin(), ivSeed.end());
  toHash.insert(toHash.end(), pointer, pointer + numberSize);
  return generichash<AeadIv>(gsl::make_span(toHash.data(), toHash.size()));
}

template <typename OutputContainer = std::vector<uint8_t>>
OutputContainer asymEncrypt(gsl::span<uint8_t const> clearData,
                            PrivateEncryptionKey const& senderKey,
                            PublicEncryptionKey const& recipientKey)
{
  using ContainerResizer = detail::container_resizer<OutputContainer>;

  auto res = ContainerResizer::resize(clearData.size() + crypto_box_MACBYTES + crypto_box_NONCEBYTES);
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
  {
    throw Errors::Exception(Errc::InvalidEncryptedDataSize, "truncated asymmetric encrypted buffer");
  }

  auto res = ContainerResizer::resize(cipherData.size() - crypto_box_MACBYTES - crypto_box_NONCEBYTES);
  detail::asymDecryptImpl(cipherData, res, senderKey, recipientKey);
  return res;
}

template <typename OutputContainer = std::vector<uint8_t>>
OutputContainer sealEncrypt(gsl::span<uint8_t const> clearData, PublicEncryptionKey const& recipientKey)
{
  using ContainerResizer = detail::container_resizer<OutputContainer>;

  // CIPHER + MAC + PUBLIC_KEY
  auto res = ContainerResizer::resize(clearData.size() + crypto_box_SEALBYTES);
  detail::sealEncryptImpl(clearData, res, recipientKey);
  return res;
}
template <typename T, typename = std::enable_if_t<IsCryptographicType<T>::value>>
Sealed<T> sealEncrypt(T const& clearData, PublicEncryptionKey const& recipientKey)
{
  Sealed<T> res;
  detail::sealEncryptImpl(clearData, res, recipientKey);
  return res;
}

template <typename OutputContainer = std::vector<uint8_t>>
OutputContainer sealDecrypt(gsl::span<uint8_t const> cipherData, EncryptionKeyPair const& recipientKeyPair)
{
  using ContainerResizer = detail::container_resizer<OutputContainer>;

  if (cipherData.size() < crypto_box_SEALBYTES)
  {
    throw Errors::Exception(Errc::InvalidSealedDataSize, "truncated sealed buffer");
  }

  auto res = ContainerResizer::resize(cipherData.size() - crypto_box_SEALBYTES);
  detail::sealDecryptImpl(cipherData, res, recipientKeyPair);
  return res;
}

template <typename T>
T sealDecrypt(Sealed<T> const& cipherData, EncryptionKeyPair const& recipientKeyPair)
{
  T res;
  detail::sealDecryptImpl(cipherData, res, recipientKeyPair);
  return res;
}

Hash prehashPassword(std::string password);

template <typename OutputContainer = std::vector<uint8_t>>
OutputContainer prehashAndEncryptPassword(std::string password, PublicEncryptionKey const& publicKey)
{
  if (password.empty())
    throw Errors::formatEx(Errc::InvalidBufferSize, "cannot hash an empty password");

  auto const prehashedPassword = generichash(password);
  return sealEncrypt(gsl::make_span(prehashedPassword.data(), prehashedPassword.size()), publicKey);
}
}
}
