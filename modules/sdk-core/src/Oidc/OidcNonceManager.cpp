#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Oidc/Nonce.hpp>
#include <Tanker/Oidc/OidcNonceManager.hpp>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <mgs/base64.hpp>
#include <mgs/base64url.hpp>
#include <nlohmann/json.hpp>

#include <range/v3/algorithm/starts_with.hpp>
#include <range/v3/range/conversion.hpp>
#include <range/v3/view/concat.hpp>

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

constexpr auto CHALLENGE_BYTE_LENGTH = 24;
OidcSignedChallenge OidcNonceManager::signOidcChallenge(
    OidcNonce const& nonce, OidcChallenge const& challenge) const
{
  static std::string const CHALLENGE_PREFIX{"oidc-verification-prefix"};

  using b64 = mgs::base64;

  if (!ranges::starts_with(challenge, CHALLENGE_PREFIX))
  {
    throw formatEx(Errors::Errc::InternalError,
                   "illformed oidc challenge: invalid prefix");
  }

  auto const b64Challenge = challenge.substr(CHALLENGE_PREFIX.length());
  std::vector<uint8_t> challengeData;
  try
  {
    challengeData = b64::decode<std::vector<uint8_t>>(b64Challenge);
  }
  catch (...)
  {
    throw formatEx(Errors::Errc::InternalError,
                   "illformed oidc challenge: invalid base64");
  }
  if (std::size(challengeData) != CHALLENGE_BYTE_LENGTH)
  {
    throw formatEx(Errors::Errc::InternalError,
                   "illformed oidc challenge: invalid challenge size");
  }

  auto const privateKey = nonceMap.find(nonce);
  if (privateKey == std::end(nonceMap))
  {
    throw formatEx(Errors::Errc::InvalidArgument,
                   "could not find state for the given nonce: {:s}",
                   nonce);
  }

  auto const signature = Crypto::sign(challengeData, privateKey->second);
  auto const payload = ranges::views::concat(challengeData, signature.base()) |
                       ranges::to<std::vector>;

  return OidcSignedChallenge{b64::encode(payload)};
};

OidcNonce Oidc::extractNonce(OidcIdToken const& idToken)
{
  namespace ba = boost::algorithm;
  using b64 = mgs::base64url_nopad;

  std::vector<std::string> res;
  ba::split(res, idToken, ba::is_any_of("."));

  auto const jwtPayload = b64::decode(res[2]);

  auto const j = nlohmann::json::parse(jwtPayload);
  auto const nonce = j.at("nonce").get<std::string>();

  return OidcNonce{nonce};
};
}
