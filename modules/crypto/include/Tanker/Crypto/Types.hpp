#pragma once

#include <Tanker/Crypto/Traits.hpp>
#include <Tanker/Crypto/base64.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <array>
#include <iterator>
#include <stdexcept>
#include <vector>

#include <gsl-lite.hpp>

#include <nlohmann/json_fwd.hpp>
#include <sodium.h>

#define KEY_IMPL_DOC(Self, ArraySize, Name)                              \
                                                                         \
public:                                                                  \
  using array_t = std::array<uint8_t, ArraySize>;                        \
                                                                         \
  static constexpr auto arraySize = ArraySize;                           \
  static constexpr char const* name = #Name;                             \
                                                                         \
  Self() = default;                                                      \
                                                                         \
  explicit Self(gsl::span<uint8_t const> data)                           \
    : Self(data.begin(), data.end())                                     \
  {                                                                      \
  }                                                                      \
                                                                         \
  template <typename InputIterator>                                      \
  Self(InputIterator begin, InputIterator end)                           \
  {                                                                      \
    auto const dist = static_cast<size_type>(std::distance(begin, end)); \
    if (dist != this->size())                                            \
      throw InvalidKeySize("invalid size for " #Name ": got " +          \
                           std::to_string(dist) + ", expected " +        \
                           std::to_string(this->size()));                \
    std::copy(begin, end, this->data());                                 \
  }                                                                      \
                                                                         \
  Self& operator=(gsl::span<uint8_t const> data)                         \
  {                                                                      \
    if (data.size() != this->size())                                     \
      throw InvalidKeySize("invalid size for " #Name ": got " +          \
                           std::to_string(data.size()) + ", expected " + \
                           std::to_string(this->size()));                \
    std::copy(data.begin(), data.end(), this->data());                   \
    return *static_cast<Self*>(this);                                    \
  }                                                                      \
                                                                         \
  ~Self() = default;                                                     \
                                                                         \
  array_t& base() & noexcept                                             \
  {                                                                      \
    return *static_cast<array_t*>(this);                                 \
  }                                                                      \
                                                                         \
  array_t const& base() const& noexcept                                  \
  {                                                                      \
    return *static_cast<array_t const*>(this);                           \
  }                                                                      \
                                                                         \
  array_t&& base() && noexcept                                           \
  {                                                                      \
    return std::move(*static_cast<array_t*>(this));                      \
  }                                                                      \
                                                                         \
  array_t const&& base() const&& noexcept                                \
  {                                                                      \
    return std::move(*static_cast<array_t const*>(this));                \
  }                                                                      \
                                                                         \
  using array_t::value_type;                                             \
  using array_t::size_type;                                              \
  using array_t::difference_type;                                        \
  using array_t::reference;                                              \
  using array_t::const_reference;                                        \
  using array_t::pointer;                                                \
  using array_t::const_pointer;                                          \
  using array_t::iterator;                                               \
  using array_t::const_iterator;                                         \
  using array_t::reverse_iterator;                                       \
  using array_t::const_reverse_iterator;                                 \
                                                                         \
  using array_t::begin;                                                  \
  using array_t::end;                                                    \
  using array_t::cbegin;                                                 \
  using array_t::cend;                                                   \
  using array_t::rbegin;                                                 \
  using array_t::rend;                                                   \
  using array_t::crbegin;                                                \
  using array_t::crend;                                                  \
  using array_t::at;                                                     \
  using array_t::front;                                                  \
  using array_t::back;                                                   \
  using array_t::operator[];                                             \
  using array_t::size;                                                   \
  using array_t::empty;                                                  \
  using array_t::data;                                                   \
  using array_t::fill;                                                   \
  using array_t::swap;                                                   \
                                                                         \
  bool is_null() const                                                   \
  {                                                                      \
    return std::all_of(begin(), end(), [](auto c) { return c == 0; });   \
  }                                                                      \
                                                                         \
  friend bool operator<(Self const& lhs, Self const& rhs) noexcept       \
  {                                                                      \
    return lhs.base() < rhs.base();                                      \
  }                                                                      \
                                                                         \
  friend bool operator>(Self const& lhs, Self const& rhs) noexcept       \
  {                                                                      \
    return lhs.base() > rhs.base();                                      \
  }                                                                      \
                                                                         \
  friend bool operator>=(Self const& lhs, Self const& rhs) noexcept      \
  {                                                                      \
    return lhs.base() >= rhs.base();                                     \
  }                                                                      \
                                                                         \
  friend bool operator<=(Self const& lhs, Self const& rhs) noexcept      \
  {                                                                      \
    return lhs.base() <= rhs.base();                                     \
  }                                                                      \
                                                                         \
  friend bool operator==(Self const& lhs, Self const& rhs) noexcept      \
  {                                                                      \
    return lhs.base() == rhs.base();                                     \
  }                                                                      \
                                                                         \
  friend bool operator!=(Self const& lhs, Self const& rhs) noexcept      \
  {                                                                      \
    return !(lhs == rhs);                                                \
  }

#define STD_ARRAY_HELPERS(Self)                                      \
  template <size_t I>                                                \
  constexpr uint8_t& get(Self& s) noexcept                           \
  {                                                                  \
    return get<I>(s.base());                                         \
  }                                                                  \
                                                                     \
  template <size_t I>                                                \
  constexpr uint8_t&& get(Self&& s) noexcept                         \
  {                                                                  \
    return get<I>(std::move(s).base());                              \
  }                                                                  \
                                                                     \
  template <size_t I>                                                \
  constexpr uint8_t const& get(Self const& s) noexcept               \
  {                                                                  \
    return get<I>(s.base());                                         \
  }                                                                  \
                                                                     \
  template <size_t I>                                                \
  constexpr uint8_t const&& get(Self const&& s) noexcept             \
  {                                                                  \
    return get<I>(std::move(s).base());                              \
  }                                                                  \
                                                                     \
  inline void swap(Self& lhs, Self& rhs)                             \
  {                                                                  \
    lhs.swap(rhs.base());                                            \
  }                                                                  \
                                                                     \
  template <>                                                        \
  class tuple_size<Self> : public tuple_size<typename Self::array_t> \
  {                                                                  \
  };                                                                 \
                                                                     \
  template <size_t I>                                                \
  class tuple_element<I, Self>                                       \
    : public tuple_element<I, typename Self::array_t>                \
  {                                                                  \
  }

#define STD_ARRAY_HELPERS_NON_TYPE_TPL_ARGS(Self, Arg1, Arg2)         \
  template <size_t I, Arg1 KT, Arg2 KU, typename Tag>                 \
  constexpr uint8_t& get(Self<KT, KU, Tag>& s) noexcept               \
  {                                                                   \
    return get<I>(s.base());                                          \
  }                                                                   \
                                                                      \
  template <size_t I, Arg1 KT, Arg2 KU, typename Tag>                 \
  constexpr uint8_t&& get(Self<KT, KU, Tag>&& s) noexcept             \
  {                                                                   \
    return get<I>(std::move(s).base());                               \
  }                                                                   \
                                                                      \
  template <size_t I, Arg1 KT, Arg2 KU, typename Tag>                 \
  constexpr uint8_t const& get(Self<KT, KU, Tag> const& s) noexcept   \
  {                                                                   \
    return get<I>(s.base());                                          \
  }                                                                   \
                                                                      \
  template <size_t I, Arg1 KT, Arg2 KU, typename Tag>                 \
  constexpr uint8_t const&& get(Self<KT, KU, Tag> const&& s) noexcept \
  {                                                                   \
    return get<I>(std::move(s).base());                               \
  }                                                                   \
                                                                      \
  template <Arg1 KT, Arg2 KU, typename Tag>                           \
  void swap(Self<KT, KU, Tag>& lhs, Self<KT, KU, Tag>& rhs)           \
  {                                                                   \
    lhs.swap(rhs.base());                                             \
  }                                                                   \
                                                                      \
  template <Arg1 KT, Arg2 KU, typename Tag>                           \
  class tuple_size<Self<KT, KU, Tag>>                                 \
    : public tuple_size<typename Self<KT, KU, Tag>::array_t>          \
  {                                                                   \
  };                                                                  \
                                                                      \
  template <size_t I, Arg1 KT, Arg2 KU, typename Tag>                 \
  class tuple_element<I, Self<KT, KU, Tag>>                           \
    : public tuple_element<I, typename Self<KT, KU, Tag>::array_t>    \
  {                                                                   \
  }

#define STD_ARRAY_HELPERS_TPL_ARG(Self)                                    \
  template <size_t I, typename T>                                          \
  constexpr uint8_t& get(Self<T>& s) noexcept                              \
  {                                                                        \
    return get<I>(s.base());                                               \
  }                                                                        \
                                                                           \
  template <size_t I, typename T>                                          \
  constexpr uint8_t&& get(Self<T>&& s) noexcept                            \
  {                                                                        \
    return get<I>(std::move(s).base());                                    \
  }                                                                        \
                                                                           \
  template <size_t I, typename T>                                          \
  constexpr uint8_t const& get(Self<T> const& s) noexcept                  \
  {                                                                        \
    return get<I>(s.base());                                               \
  }                                                                        \
                                                                           \
  template <size_t I, typename T>                                          \
  constexpr uint8_t const&& get(Self<T> const&& s) noexcept                \
  {                                                                        \
    return get<I>(std::move(s).base());                                    \
  }                                                                        \
                                                                           \
  template <typename T>                                                    \
  void swap(Self<T>& lhs, Self<T>& rhs)                                    \
  {                                                                        \
    lhs.swap(rhs.base());                                                  \
  }                                                                        \
                                                                           \
  template <typename T>                                                    \
  class tuple_size<Self<T>> : public tuple_size<typename Self<T>::array_t> \
  {                                                                        \
  };                                                                       \
                                                                           \
  template <size_t I, typename T>                                          \
  class tuple_element<I, Self<T>>                                          \
    : public tuple_element<I, typename Self<T>::array_t>                   \
  {                                                                        \
  }

#define KEY_IMPL(Self, ArraySize) KEY_IMPL_DOC(Self, ArraySize, Self)

namespace Tanker
{
namespace Crypto
{
class InvalidKeySize : public std::exception
{
public:
  InvalidKeySize(std::string const& msg) : _msg(msg)
  {
  }

  char const* what() const noexcept override
  {
    return _msg.c_str();
  }

private:
  std::string _msg;
};

enum class KeyUsage
{
  Signature,
  Encryption,
};

enum class KeyType
{
  Private,
  Public,
};

template <KeyType Type, KeyUsage Usage, typename = void>
class AsymmetricKey;

// using private inheritance here (UB as the standard says but it's ok TM)
// see https://stackoverflow.com/a/4354072
template <typename T>
class AsymmetricKey<KeyType::Private, KeyUsage::Signature, T>
  : std::array<uint8_t, crypto_sign_SECRETKEYBYTES>
{
  KEY_IMPL_DOC(AsymmetricKey, crypto_sign_SECRETKEYBYTES, PrivateSignatureKey)
};

template <typename T>
class AsymmetricKey<KeyType::Public, KeyUsage::Signature, T>
  : std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>
{
  KEY_IMPL_DOC(AsymmetricKey, crypto_sign_PUBLICKEYBYTES, PublicSignatureKey)
};

template <typename T>
class AsymmetricKey<KeyType::Private, KeyUsage::Encryption, T>
  : std::array<uint8_t, crypto_box_SECRETKEYBYTES>
{
  KEY_IMPL_DOC(AsymmetricKey, crypto_box_SECRETKEYBYTES, PrivateEncryptionKey)
};

template <typename T>
class AsymmetricKey<KeyType::Public, KeyUsage::Encryption, T>
  : std::array<uint8_t, crypto_box_PUBLICKEYBYTES>
{
  KEY_IMPL_DOC(AsymmetricKey, crypto_box_PUBLICKEYBYTES, PublicEncryptionKey)
};

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

template <typename T>
using PublicSignatureKeyBase =
    AsymmetricKey<KeyType::Public, KeyUsage::Signature, T>;

using PublicSignatureKey = PublicSignatureKeyBase<void>;

using PrivateSignatureKey =
    AsymmetricKey<KeyType::Private, KeyUsage::Signature>;
using PublicEncryptionKey =
    AsymmetricKey<KeyType::Public, KeyUsage::Encryption>;
using PrivateEncryptionKey =
    AsymmetricKey<KeyType::Private, KeyUsage::Encryption>;

using SignatureKeyPair = KeyPair<KeyUsage::Signature>;
using EncryptionKeyPair = KeyPair<KeyUsage::Encryption>;

template <typename>
class BasicHash : std::array<uint8_t, crypto_generichash_BYTES>
{
  KEY_IMPL(BasicHash, crypto_generichash_BYTES);
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

#define DEFINE_TYPE(name, size)          \
  class name : std::array<uint8_t, size> \
  {                                      \
    KEY_IMPL(name, size)                 \
  }

DEFINE_TYPE(Signature, crypto_sign_BYTES);
DEFINE_TYPE(Mac, crypto_aead_xchacha20poly1305_ietf_ABYTES);
DEFINE_TYPE(SymmetricKey, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
DEFINE_TYPE(AeadIv, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
DEFINE_TYPE(SealedPrivateEncryptionKey,
            crypto_box_SECRETKEYBYTES + crypto_box_SEALBYTES);
DEFINE_TYPE(SealedPrivateSignatureKey,
            crypto_sign_SECRETKEYBYTES + crypto_box_SEALBYTES);
DEFINE_TYPE(EncryptedSymmetricKey,
            crypto_aead_xchacha20poly1305_ietf_KEYBYTES + crypto_box_MACBYTES +
                crypto_box_NONCEBYTES);
DEFINE_TYPE(SealedSymmetricKey,
            crypto_aead_xchacha20poly1305_ietf_KEYBYTES + crypto_box_SEALBYTES);

#undef DEFINE_TYPE

template <KeyType Type, KeyUsage Usage, typename T>
struct is_cryptographic_type<AsymmetricKey<Type, Usage, T>> : std::true_type
{
};

template <typename T>
struct is_cryptographic_type<BasicHash<T>> : std::true_type
{
};

#define IS_CRYPTO_TRAIT(Self)                         \
  template <>                                         \
  struct is_cryptographic_type<Self> : std::true_type \
  {                                                   \
  }

IS_CRYPTO_TRAIT(Signature);
IS_CRYPTO_TRAIT(Mac);
IS_CRYPTO_TRAIT(SymmetricKey);
IS_CRYPTO_TRAIT(SealedPrivateEncryptionKey);
IS_CRYPTO_TRAIT(SealedPrivateSignatureKey);
IS_CRYPTO_TRAIT(EncryptedSymmetricKey);
IS_CRYPTO_TRAIT(SealedSymmetricKey);

template <typename T,
          typename = std::enable_if_t<is_cryptographic_type<T>::value>>
constexpr std::size_t serialized_size(T const& val)
{
  return val.arraySize;
}

template <typename T,
          typename = std::enable_if_t<is_cryptographic_type<T>::value>>
void from_serialized(Serialization::SerializedSource& ss, T& val)
{
  auto sp = ss.read(val.size());
  std::copy(sp.begin(), sp.end(), val.begin());
}

template <typename T,
          typename = std::enable_if_t<is_cryptographic_type<T>::value>>
std::uint8_t* to_serialized(std::uint8_t* it, T const& val)
{
  return std::copy(val.begin(), val.end(), it);
}
}
}

namespace std
{
STD_ARRAY_HELPERS_NON_TYPE_TPL_ARGS(::Tanker::Crypto::AsymmetricKey,
                                    ::Tanker::Crypto::KeyType,
                                    ::Tanker::Crypto::KeyUsage);
STD_ARRAY_HELPERS_TPL_ARG(::Tanker::Crypto::BasicHash);
STD_ARRAY_HELPERS(::Tanker::Crypto::Mac);
STD_ARRAY_HELPERS(::Tanker::Crypto::Signature);
STD_ARRAY_HELPERS(::Tanker::Crypto::SymmetricKey);
STD_ARRAY_HELPERS(::Tanker::Crypto::SealedPrivateEncryptionKey);
STD_ARRAY_HELPERS(::Tanker::Crypto::SealedPrivateSignatureKey);
STD_ARRAY_HELPERS(::Tanker::Crypto::EncryptedSymmetricKey);
STD_ARRAY_HELPERS(::Tanker::Crypto::SealedSymmetricKey);
}

#undef KEY_IMPL
#undef STD_ARRAY_HELPERS_NON_TYPE_TPL_ARGS
#undef STD_ARRAY_HELPERS_TPL_ARG
#undef STD_ARRAY_HELPERS
#undef IS_CRYPTO_TRAIT

namespace nlohmann
{
template <typename CryptoType>
struct adl_serializer<
    CryptoType,
    std::enable_if_t<Tanker::Crypto::is_cryptographic_type<CryptoType>::value>>
{
  template <typename BasicJsonType>
  static void to_json(BasicJsonType& j, CryptoType const& value)
  {
    j = Tanker::base64::encode(value);
  }

  template <typename BasicJsonType>
  static void from_json(BasicJsonType const& j, CryptoType& value)
  {
    value = Tanker::base64::decode<CryptoType>(j.template get<std::string>());
  }
};
}
