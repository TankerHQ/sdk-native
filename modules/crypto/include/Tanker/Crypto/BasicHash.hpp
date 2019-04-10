#pragma once

#include <Tanker/Crypto/IsCryptographicType.hpp>

#include <Tanker/Crypto/detail/ArrayHelpers.hpp>
#include <Tanker/Crypto/detail/CryptographicTypeImpl.hpp>

#include <sodium/crypto_generichash.h>

#include <array>
#include <cstdint>
#include <type_traits>

namespace Tanker
{
namespace Crypto
{
template <typename>
class BasicHash : std::array<std::uint8_t, crypto_generichash_BYTES>
{
  TANKER_CRYPTO_CRYPTOGRAPHIC_TYPE_IMPL(BasicHash,
                                        crypto_generichash_BYTES,
                                        BasicHash);
};

template <typename T>
struct IsCryptographicType<BasicHash<T>> : std::true_type
{
};
}
}

namespace std
{
TANKER_CRYPTO_STD_TUPLE_SIZE_ELEMENT_TPL_ARG(::Tanker::Crypto::BasicHash)
}
