#pragma once

#include <Tanker/Crypto/detail/ArrayHelpers.hpp>
#include <Tanker/Crypto/detail/CryptographicType.hpp>
#include <Tanker/Crypto/detail/IsCryptographicType.hpp>

#include <sodium/crypto_box.h>
#include <sodium/crypto_sign.h>

namespace Tanker
{
namespace Crypto
{
TANKER_CRYPTO_CRYPTOGRAPHIC_TYPE(SealedPrivateSignatureKey,
                                 crypto_sign_SECRETKEYBYTES +
                                     crypto_box_SEALBYTES)
TANKER_CRYPTO_IS_CRYPTOGRAPHIC_TYPE(SealedPrivateSignatureKey)
}
}

namespace std
{
TANKER_CRYPTO_STD_TUPLE_SIZE_ELEMENT(
    ::Tanker::Crypto::SealedPrivateSignatureKey)
}
