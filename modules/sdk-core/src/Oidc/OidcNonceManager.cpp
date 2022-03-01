#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Oidc/Nonce.hpp>
#include <Tanker/Oidc/OidcNonceManager.hpp>

namespace Tanker
{
OidcNonce OidcNonceManager::createOidcNonce()
{
  auto const signatureKeyPair = Crypto::makeSignatureKeyPair();

  auto const nonce = OidcNonce{mgs::base64::encode(signatureKeyPair.publicKey)};
  nonceMap.emplace(nonce, signatureKeyPair.privateKey);
  return nonce;
};

void OidcNonceManager::setTestNonce(OidcNonce const& nonce)
{
  _testNonce = nonce;
}

std::optional<OidcNonce> OidcNonceManager::getTestNonce() const
{
  return _testNonce;
}
}
