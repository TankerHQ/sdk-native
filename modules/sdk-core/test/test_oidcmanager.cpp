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
