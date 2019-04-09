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
template <KeyType Type, KeyUsage Usage, typename = void>
class AsymmetricKey;

template <KeyType Type, KeyUsage Usage, typename T>
struct IsCryptographicType<AsymmetricKey<Type, Usage, T>> : std::true_type
{
};
}
}

namespace std
{
TANKER_CRYPTO_ARRAY_HELPERS_NON_TYPE_TPL_ARGS(::Tanker::Crypto::AsymmetricKey,
                                              ::Tanker::Crypto::KeyType,
                                              ::Tanker::Crypto::KeyUsage);
}
