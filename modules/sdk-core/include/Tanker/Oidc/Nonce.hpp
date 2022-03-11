#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Types/OidcIdToken.hpp>
#include <Tanker/Types/OidcNonce.hpp>

namespace Tanker::Oidc
{
Nonce extractNonce(OidcIdToken const& idToken);
class RawNonce
  : public Crypto::BasicCryptographicType<RawNonce,
                                          Crypto::PublicSignatureKey::arraySize>
{
  using base_t::base_t;
};
}
