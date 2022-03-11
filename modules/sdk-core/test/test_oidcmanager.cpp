#include <catch2/catch.hpp>

#include <Helpers/Errors.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Errors/Errc.hpp>
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

TEST_CASE("Oidc::NonceManager")
{
  NonceManager nonceManager{};
  auto const challengeSize = 24;
  auto const prefix = "oidc-verification-prefix";

  SECTION("creates a different nonce each time")
  {
    auto const nonce1 = nonceManager.createOidcNonce();
    auto const nonce2 = nonceManager.createOidcNonce();

    CHECK(nonce1 != nonce2);
  }

  SECTION("rejects ill-formed challenge")
  {
    auto const wrongPrefix = fmt::format(
        "wrong-prefix{}", mgs::base64::encode(makeBuffer(challengeSize)));
    auto b64Challenge = mgs::base64url::encode(makeBuffer(challengeSize));
    b64Challenge[2] = '-';
    auto const wrongEncoding = fmt::format("{}{}", prefix, b64Challenge);
    auto const challengeTooLong = fmt::format(
        "{}{}", prefix, mgs::base64::encode(makeBuffer(challengeSize + 1)));
    auto const challengeTooShort = fmt::format(
        "{}{}", prefix, mgs::base64::encode(makeBuffer(challengeSize - 1)));

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
    auto const challenge =
        Challenge{prefix + mgs::base64::encode(makeBuffer(challengeSize))};

    TANKER_CHECK_THROWS_WITH_CODE(
        nonceManager.signOidcChallenge(nonce, challenge),
        Errors::Errc::InvalidArgument);
  }

  SECTION("signs given challenge with nonce private key")
  {
    auto const nonce = nonceManager.createOidcNonce();
    auto const challengeData = makeBuffer(challengeSize);
    auto const challenge =
        Challenge{prefix + mgs::base64::encode(challengeData)};

    auto const signedChallenge =
        mgs::base64::decode(nonceManager.signOidcChallenge(nonce, challenge));

    auto const begin = std::next(std::cbegin(signedChallenge), challengeSize);
    auto const signature = Signature(begin, std::cend(signedChallenge));
    auto const pubKey = AsymmetricKey<KeyType::Public, KeyUsage::Signature>{
        mgs::base64::decode(nonce)};

    CHECK_NOTHROW(verify(challengeData, signature, pubKey));
  }
}
