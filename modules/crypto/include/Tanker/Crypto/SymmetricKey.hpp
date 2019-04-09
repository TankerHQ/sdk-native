#pragma once

#include <Tanker/Crypto/detail/CryptographicType.hpp>
#include <Tanker/Crypto/detail/IsCryptographicType.hpp>
#include <Tanker/Crypto/detail/ArrayHelpers.hpp>

#include <sodium/crypto_aead_xchacha20poly1305.h>

namespace Tanker
{
namespace Crypto
{
TANKER_CRYPTO_CRYPTOGRAPHIC_TYPE(SymmetricKey,
                                 crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
TANKER_CRYPTO_IS_CRYPTOGRAPHIC_TYPE(SymmetricKey)
}
}

namespace std
{
TANKER_CRYPTO_STD_TUPLE_SIZE_ELEMENT(::Tanker::Crypto::SymmetricKey)
}
