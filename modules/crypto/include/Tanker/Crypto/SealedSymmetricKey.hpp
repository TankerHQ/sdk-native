#pragma once

#include <Tanker/Crypto/detail/ArrayHelpers.hpp>
#include <Tanker/Crypto/detail/CryptographicType.hpp>
#include <Tanker/Crypto/detail/IsCryptographicType.hpp>

#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_box.h>

namespace Tanker
{
namespace Crypto
{
TANKER_CRYPTO_CRYPTOGRAPHIC_TYPE(SealedSymmetricKey,
                                 crypto_aead_xchacha20poly1305_ietf_KEYBYTES +
                                     crypto_box_SEALBYTES)
TANKER_CRYPTO_IS_CRYPTOGRAPHIC_TYPE(SealedSymmetricKey)
}
}

namespace std
{
TANKER_CRYPTO_STD_TUPLE_SIZE_ELEMENT(::Tanker::Crypto::SealedSymmetricKey)
}
