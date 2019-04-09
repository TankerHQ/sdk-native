#pragma once

#include <Tanker/Crypto/detail/CryptographicType.hpp>
#include <Tanker/Crypto/detail/IsCryptographicType.hpp>
#include <Tanker/Crypto/detail/ArrayHelpers.hpp>

#include <sodium/crypto_sign.h>

namespace Tanker
{
namespace Crypto
{
TANKER_CRYPTO_CRYPTOGRAPHIC_TYPE(Signature, crypto_sign_BYTES)
TANKER_CRYPTO_IS_CRYPTOGRAPHIC_TYPE(Signature)
}
}

namespace std
{
TANKER_CRYPTO_STD_TUPLE_SIZE_ELEMENT(::Tanker::Crypto::Signature)
}
