#pragma once

#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Types/OidcChallenge.hpp>
#include <Tanker/Types/OidcIdToken.hpp>
#include <Tanker/Types/OidcNonce.hpp>

#include <boost/container/flat_map.hpp>

#include <optional>

namespace Tanker::Oidc
{
inline constexpr auto CHALLENGE_BYTE_LENGTH = 24;
inline constexpr std::string_view CHALLENGE_PREFIX = "oidc-verification-prefix";

class NonceManager
{
public:
  Nonce createOidcNonce();
  SignedChallenge signOidcChallenge(Nonce const& nonce, Challenge const& challenge);

  void setTestNonce(Nonce const& nonce);
  std::optional<Nonce> testNonce() const;

private:
  std::optional<Nonce> _testNonce;
  boost::container::flat_map<Nonce, Crypto::PrivateSignatureKey> nonceMap;
};
}
