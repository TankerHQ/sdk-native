#pragma once

#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Types/OidcChallenge.hpp>
#include <Tanker/Types/OidcIdToken.hpp>
#include <Tanker/Types/OidcNonce.hpp>

#include <boost/container/flat_map.hpp>

#include <optional>

namespace Tanker
{
class OidcNonceManager
{
public:
  OidcNonce createOidcNonce();

private:
  boost::container::flat_map<OidcNonce, Crypto::PrivateSignatureKey> nonceMap{};
};
}