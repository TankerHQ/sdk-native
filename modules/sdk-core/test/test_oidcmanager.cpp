#include <catch2/catch.hpp>

#include <Helpers/Errors.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Oidc/Nonce.hpp>
#include <Tanker/Oidc/NonceManager.hpp>

#include <mgs/base64.hpp>
#include <mgs/base64url.hpp>

using namespace Tanker;
using namespace Tanker::Crypto;
using namespace Tanker::Oidc;

namespace
{
std::vector<uint8_t> makeBuffer(size_t size)
{
  auto challenge = std::vector<uint8_t>(size);
  Crypto::randomFill(challenge);
  return challenge;
}
}

TEST_CASE("Oidc::extractNonce")
{
  auto const nonce = Nonce{"OZwTLhhp0C/imcuwrhsHxSnltK7BmdwgnQXUjJZXVGI="};
  // Test ID Token with PII removed. As such the signature is broken
  auto const idToken =
      "eyJhbGciOiJSUzI1NiIsImtpZCI6ImNlYzEzZGViZjRiOTY0Nzk2ODM3MzYyMDUwODI0NjZj"
      "MTQ3OTdiZDAiLCJ0eXAiOiJKV1QifQ."
      "eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxMDA3MTQ5Njc4"
      "OTE5LWQ4MDViYjduajVkOWRoMTI2NTA5NjkwN3BmZDdxdjVyLmFwcHMuZ29vZ2xldXNlcmNv"
      "bnRlbnQuY29tIiwiYXVkIjoiMTAwNzE0OTY3ODkxOS1kODA1YmI3bmo1ZDlkaDEyNjUwOTY5"
      "MDdwZmQ3cXY1ci5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjAwMDAwMDAw"
      "MDAwMDAwMDAwMDAwMCIsImVtYWlsIjoiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hh"
      "c2giOiJ2Y2F1QjIzTlNEMDdfZ2FoWUxJQ1pRIiwibm9uY2UiOiJPWndUTGhocDBDL2ltY3V3"
      "cmhzSHhTbmx0SzdCbWR3Z25RWFVqSlpYVkdJPSIsImlhdCI6MTY0OTE2ODMyNiwiZXhwIjox"
      "NjQ5MTcxOTI2fQ."
      "Ty_PJzuuxMIAKuV3-JCdNHmlHTOUngh1ozDMSd_U8xvF-VuXQSSTx6IKejaLaj4NNMl6sgAp"
      "ptGnzF_eWJnDdpiHIOYNDwjJdC6WBfuWkFda4k4Aj1BcnYFaVeA4xBmO7BI4xVKAsCHMC6l9"
      "kAnHc5vxoW99T3pIoxOUfcG-G4q2PZHRDLzy3cTCOFlI86g1yavvr_rpxSl3GFpaEdANKBgL"
      "GArX5pTPgD1yaBbj68cmejxohpBlb5gziRze7_ga-A00SdoSFyu9ExNeyohxQZekcWdTni6g"
      "ecss2oqEVkO5ei4XZ1JkYuFsTBeTH_mhk6gysWXOvcCE4-NxkBjnlA";

  SECTION("extract nonce from ID Token")
  {
    auto const testNonce = extractNonce(idToken);

    CHECK(testNonce == nonce);
  }
}

TEST_CASE("Oidc::NonceManager")
{
  NonceManager nonceManager{};

  SECTION("creates a different nonce each time")
  {
    auto const nonce1 = nonceManager.createOidcNonce();
    auto const nonce2 = nonceManager.createOidcNonce();

    CHECK(nonce1 != nonce2);
  }

  SECTION("rejects ill-formed challenge")
  {
    auto const wrongPrefix =
        fmt::format("wrong-prefix{}",
                    mgs::base64::encode(makeBuffer(CHALLENGE_BYTE_LENGTH)));
    auto b64Challenge =
        mgs::base64url::encode(makeBuffer(CHALLENGE_BYTE_LENGTH));
    b64Challenge[2] = '-';
    auto const wrongEncoding =
        fmt::format("{}{}", CHALLENGE_PREFIX, b64Challenge);
    auto const challengeTooLong =
        fmt::format("{}{}",
                    CHALLENGE_PREFIX,
                    mgs::base64::encode(makeBuffer(CHALLENGE_BYTE_LENGTH + 1)));
    auto const challengeTooShort =
        fmt::format("{}{}",
                    CHALLENGE_PREFIX,
                    mgs::base64::encode(makeBuffer(CHALLENGE_BYTE_LENGTH - 1)));

    auto const nonce = nonceManager.createOidcNonce();

    TANKER_CHECK_THROWS_WITH_CODE(
        nonceManager.signOidcChallenge(nonce, Oidc::Challenge{wrongPrefix}),
        Errors::Errc::InternalError);
    TANKER_CHECK_THROWS_WITH_CODE(
        nonceManager.signOidcChallenge(nonce, Oidc::Challenge{wrongEncoding}),
        Errors::Errc::InternalError);
    TANKER_CHECK_THROWS_WITH_CODE(nonceManager.signOidcChallenge(
                                      nonce, Oidc::Challenge{challengeTooLong}),
                                  Errors::Errc::InternalError);
    TANKER_CHECK_THROWS_WITH_CODE(
        nonceManager.signOidcChallenge(nonce,
                                       Oidc::Challenge{challengeTooShort}),
        Errors::Errc::InternalError);
  }

  SECTION("rejects unknown nonce")
  {
    auto const nonce =
        Nonce{mgs::base64::encode(makeBuffer(PublicSignatureKey::arraySize))};
    auto const challenge = Challenge{
        fmt::format("{}{}",
                    CHALLENGE_PREFIX,
                    mgs::base64::encode(makeBuffer(CHALLENGE_BYTE_LENGTH)))};

    TANKER_CHECK_THROWS_WITH_CODE(
        nonceManager.signOidcChallenge(nonce, challenge),
        Errors::Errc::InvalidArgument);
  }

  SECTION("signs given challenge with nonce private key")
  {
    auto const nonce = nonceManager.createOidcNonce();
    auto const challengeData = makeBuffer(CHALLENGE_BYTE_LENGTH);
    auto const challenge = Challenge{fmt::format(
        "{}{}", CHALLENGE_PREFIX, mgs::base64::encode(challengeData))};

    auto const signedChallenge =
        nonceManager.signOidcChallenge(nonce, challenge);

    auto const signature =
        Signature(mgs::base64::decode(signedChallenge.signature));
    auto const pubKey = AsymmetricKey<KeyType::Public, KeyUsage::Signature>{
        mgs::base64::decode(nonce)};

    CHECK_NOTHROW(verify(challengeData, signature, pubKey));
  }
}
