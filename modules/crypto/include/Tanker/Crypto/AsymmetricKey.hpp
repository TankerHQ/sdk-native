#pragma once

#include <Tanker/Crypto/IsCryptographicType.hpp>
#include <Tanker/Crypto/KeyType.hpp>
#include <Tanker/Crypto/KeyUsage.hpp>

#include <Tanker/Crypto/detail/ArrayHelpers.hpp>

#include <type_traits>

namespace Tanker
{
namespace Crypto
{
template <KeyType Type, KeyUsage Usage>
class AsymmetricKey;

template <KeyType Type, KeyUsage Usage>
struct IsCryptographicType<AsymmetricKey<Type, Usage>> : std::true_type
{
};
}
}

namespace std
{
TANKER_CRYPTO_STD_TUPLE_SIZE_ELEMENT_NON_TYPE_TPL_ARGS(
    ::Tanker::Crypto::AsymmetricKey,
    ::Tanker::Crypto::KeyType,
    ::Tanker::Crypto::KeyUsage)
}
