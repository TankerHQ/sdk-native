#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>

#include <sodium/crypto_aead_xchacha20poly1305.h>

#include <tuple>
#include <type_traits>

namespace Tanker
{
namespace Crypto
{
extern template class BasicCryptographicType<class AeadIv, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>;

class AeadIv : public BasicCryptographicType<AeadIv, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>
{
  using base_t::base_t;
};
}
}

#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/Crypto/Serialization/Serialization.hpp>
