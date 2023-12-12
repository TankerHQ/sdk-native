#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Oidc/Nonce.hpp>
#include <Tanker/Oidc/NonceManager.hpp>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <mgs/base64.hpp>
#include <mgs/base64url.hpp>
#include <nlohmann/json.hpp>

#include <range/v3/algorithm/starts_with.hpp>
#include <range/v3/view/concat.hpp>

namespace Tanker::Oidc
{
Nonce NonceManager::createOidcNonce()
{
  auto const signatureKeyPair = Crypto::makeSignatureKeyPair();

  auto const nonce = Nonce{mgs::base64url_nopad::encode(signatureKeyPair.publicKey)};
  nonceMap.emplace(nonce, signatureKeyPair.privateKey);
  return nonce;
}

void NonceManager::setTestNonce(Nonce const& nonce)
{
  _testNonce = nonce;
}

std::optional<Nonce> NonceManager::testNonce() const
{
  return _testNonce;
}

namespace
{
std::vector<uint8_t> decodeChallenge(Challenge const& challenge)
{
  using b64 = mgs::base64;

  if (!ranges::starts_with(challenge, CHALLENGE_PREFIX))
  {
    throw formatEx(Errors::Errc::InternalError, "illformed oidc challenge: invalid prefix");
  }

  auto const b64Challenge = challenge.substr(CHALLENGE_PREFIX.length());
  std::vector<uint8_t> challengeData;
  try
  {
    challengeData = b64::decode<std::vector<uint8_t>>(b64Challenge);
  }
  catch (...)
  {
    throw formatEx(Errors::Errc::InternalError, "illformed oidc challenge: invalid base64");
  }

  if (challengeData.size() != CHALLENGE_BYTE_LENGTH)
  {
    throw formatEx(Errors::Errc::InternalError, "illformed oidc challenge: invalid challenge size");
  }

  return challengeData;
}
}

SignedChallenge NonceManager::signOidcChallenge(Nonce const& nonce, Challenge const& challenge)
{
  using b64 = mgs::base64;

  auto const challengeData = decodeChallenge(challenge);

  auto const privateKeyIt = nonceMap.find(nonce);
  if (privateKeyIt == std::end(nonceMap))
  {
    throw formatEx(Errors::Errc::InvalidArgument, "could not find state for the given nonce: {:s}", nonce);
  }
  nonceMap.erase(privateKeyIt);

  auto const signature = b64::encode(Crypto::sign(challengeData, privateKeyIt->second));
  return SignedChallenge{
      Challenge{b64::encode(challengeData)},
      ChallengeSignature{signature},
  };
}

Nonce extractNonce(std::string const& idToken)
{
  namespace ba = boost::algorithm;
  using b64 = mgs::base64url_nopad;

  std::vector<std::string> res;
  ba::split(res, idToken, ba::is_any_of("."));

  auto const jwtPayload = b64::decode(res[1]);

  auto const j = nlohmann::json::parse(jwtPayload);
  return j.at("nonce").get<Nonce>();
}
}
