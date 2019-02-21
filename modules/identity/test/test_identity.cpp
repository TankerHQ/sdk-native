#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Identity/Identity.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/UserToken.hpp>
#include <Tanker/Identity/Utils.hpp>
#include <Tanker/Types/UserId.hpp>

#include <doctest.h>
#include <fmt/format.h>
#include <gsl-lite.hpp>
#include <nlohmann/json.hpp>

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std::string_literals;
namespace Tanker
{
using namespace type_literals;
namespace Identity
{
namespace
{
auto const GOOD_USER_TOKEN =
    "eyJlcGhlbWVyYWxfcHVibGljX3NpZ25hdHVyZV9rZXkiOiJCRUtpZ0t0YkkxVlR1U1NKanpMTE"
    "NNY2ZiTi96OEtYci9oNVcyYnp6ZU5VPSIsImVwaGVtZXJhbF9wcml2YXRlX3NpZ25hdHVyZV9r"
    "ZXkiOiJHYlFidnhsMlZRTklOTjgzM1BBcGxDcTJGRG5kYnpZdWpiNzgwbUtISnJBRVFxS0FxMX"
    "NqVlZPNUpJbVBNc3NJeHg5czMvUHdwZXYrSGxiWnZQTjQxUT09IiwidXNlcl9pZCI6Ik9UUFJX"
    "ODFDU1Nja0UyWExYbEFHbi8rZ1k0b3J2ejV4SWpOZUV3blNNems9IiwiZGVsZWdhdGlvbl9zaW"
    "duYXR1cmUiOiI4L003M1J1Y0ttNzBWQkl2WEpWZEx1MUtJUElpaEZqYzk4RjNseXZlSGJ6UWZp"
    "clpzUjhmald2SEFsb1lNOE1uZ282NEpMMlU2UmZ1VENTY21qS2lBZz09IiwidXNlcl9zZWNyZX"
    "QiOiJ2alZxWlVYNTVEbDJBc3J2NXlRczV4TElpaUNxYm00UmRYc0JUNkpVRjE0PSJ9"s;

auto const GOOD_IDENTITY =
    "eyJkZWxlZ2F0aW9uIjp7ImVwaGVtZXJhbF9zaWduYXR1cmUiOiI4L003M1J1Y0ttNzBWQkl2WE"
    "pWZEx1MUtJUElpaEZqYzk4RjNseXZlSGJ6UWZpclpzUjhmald2SEFsb1lNOE1uZ282NEpMMlU2"
    "UmZ1VENTY21qS2lBZz09IiwiZXBoZW1lcmFsX3NpZ25hdHVyZV9wcml2YXRlX2tleSI6IkdiUW"
    "J2eGwyVlFOSU5OODMzUEFwbENxMkZEbmRiell1amI3ODBtS0hKckFFUXFLQXExc2pWVk81Sklt"
    "UE1zc0l4eDlzMy9Qd3BlditIbGJadlBONDFRPT0iLCJlcGhlbWVyYWxfc2lnbmF0dXJlX3B1Ym"
    "xpY19rZXkiOiJCRUtpZ0t0YkkxVlR1U1NKanpMTENNY2ZiTi96OEtYci9oNVcyYnp6ZU5VPSJ9"
    "LCJ0cnVzdGNoYWluX2lkIjoibVEyWDRyTStVV1ZWZzJlQzZhVGgwbmY4a25XRkkxWWc3SnhhQj"
    "BVMnA5ND0iLCJ1c2VyX2lkIjoiT1RQUlc4MUNTU2NrRTJYTFhsQUduLytnWTRvcnZ6NXhJak5l"
    "RXduU016az0iLCJ1c2VyX3NlY3JldCI6InZqVnFaVVg1NURsMkFzcnY1eVFzNXhMSWlpQ3FibT"
    "RSZFhzQlQ2SlVGMTQ9In0="s;

auto const userIdString = "OTPRW81CSSckE2XLXlAGn/+gY4orvz5xIjNeEwnSMzk="s;
auto const userId = base64::decode<UserId>(userIdString);

auto const userSecret = base64::decode<Tanker::Crypto::SymmetricKey>(
    "vjVqZUX55Dl2Asrv5yQs5xLIiiCqbm4RdXsBT6JUF14=");

auto const trustchainIdString = "mQ2X4rM+UWVVg2eC6aTh0nf8knWFI1Yg7JxaB0U2p94="s;
auto const trustchainId = base64::decode<TrustchainId>(trustchainIdString);

auto const publicKey = base64::decode<Tanker::Crypto::PublicSignatureKey>(
    "BEKigKtbI1VTuSSJjzLLCMcfbN/z8KXr/h5W2bzzeNU=");

auto const privateKeyString =
    "GbQbvxl2VQNINN833PAplCq2FDndbzYujb780mKHJrAEQqKAq1sjVVO5JImPMssIxx9s3/"
    "Pwpev+HlbZvPN41Q=="s;

auto const privateKey =
    base64::decode<Tanker::Crypto::PrivateSignatureKey>(privateKeyString);

auto const signature = base64::decode<Tanker::Crypto::Signature>(
    "8/"
    "M73RucKm70VBIvXJVdLu1KIPIihFjc98F3lyveHbzQfirZsR8fjWvHAloYM8Mngo64JL2U6Rfu"
    "TCScmjKiAg==");

void checkUserSecret(Tanker::Crypto::SymmetricKey const& userSecret,
                     UserId const& userId)
{
  auto const check = userSecretHash(gsl::make_span(userSecret)
                                        .subspan(0, USER_SECRET_SIZE - 1)
                                        .as_span<uint8_t const>(),
                                    userId);
  if (check[0] != userSecret[USER_SECRET_SIZE - 1])
    throw std::invalid_argument("bad user secret");
}
}

TEST_CASE("checkUserSecret")
{
  CHECK_NOTHROW(checkUserSecret(userSecret, userId));
}

TEST_CASE("generate Identity")
{
  SUBCASE("should throw given empty userId")
  {
    CHECK_THROWS_AS(createIdentity("trustchainID", "privateKey", ""_uid),
                    std::invalid_argument);
  }
  SUBCASE("should throw given empty trustchainId")
  {
    CHECK_THROWS_AS(createIdentity("", "privateKey", "userId"_uid),
                    std::invalid_argument);
  }
  SUBCASE("should throw given empty privateKey")
  {
    CHECK_THROWS_AS(createIdentity("trustchainID", "", "userId"_uid),
                    std::invalid_argument);
  }
  SUBCASE("We can create an identity from strings")
  {
    CHECK_NOTHROW(createIdentity(
        trustchainIdString, privateKeyString, SUserId{userIdString}));
  }
  SUBCASE("We can construct an identity from a good string")
  {
    auto identity = from_string<Identity>(GOOD_IDENTITY);
    CHECK(identity.delegation.ephemeralKeyPair.publicKey == publicKey);
    CHECK(identity.delegation.ephemeralKeyPair.privateKey == privateKey);
    CHECK(identity.delegation.userId == userId);
    CHECK(identity.delegation.signature == signature);
    CHECK(identity.userSecret == userSecret);
  }
  SUBCASE("We can get back the same string from an Identity")
  {
    auto const identity = Identity(
        UserToken{{{publicKey, privateKey}, userId, signature}, userSecret},
        trustchainId);
    auto const identity2 = from_string<Identity>(to_string(identity));
    CHECK(identity == identity2);
  }
}

TEST_CASE("ugprade a user token to an identity")
{
  SUBCASE("We can upgrade a userToken to an identity")
  {
    auto identity = from_string<Identity>(
        upgradeUserToken(trustchainIdString, GOOD_USER_TOKEN));
    CHECK(identity.delegation.ephemeralKeyPair.publicKey == publicKey);
    CHECK(identity.delegation.ephemeralKeyPair.privateKey == privateKey);
    CHECK(identity.delegation.userId == userId);
    CHECK(identity.delegation.signature == signature);
    CHECK(identity.userSecret == userSecret);
    CHECK(identity.trustchainId == trustchainId);
  }
}

TEST_CASE("get a public identity")
{
  auto const identityStr =
      createIdentity(trustchainIdString, privateKeyString, "alice"_uid);
  SUBCASE("get a public identity from a normal identity")
  {
    auto const publicIdentityStr = getPublicIdentity(identityStr);
    auto const publicIdentity = from_string<PublicIdentity>(publicIdentityStr);
    auto const aliceO = obfuscateUserId("alice"_uid, trustchainId);
    auto* p = mpark::get_if<PublicNormalIdentity>(&publicIdentity);
    CHECK(p);
    CHECK_EQ(p->trustchainId, trustchainId);
    CHECK_EQ(p->userId, aliceO);
  }
}

TEST_CASE("Generate user token")
{
  SUBCASE("should throw given empty userId")
  {
    CHECK_THROWS_AS(generateUserToken("trustchainID", "privateKey", ""_uid),
                    std::invalid_argument);
  }
  SUBCASE("should throw given empty trustchainId")
  {
    CHECK_THROWS_AS(generateUserToken("", "privateKey", "userId"_uid),
                    std::invalid_argument);
  }
  SUBCASE("should throw given empty privateKey")
  {
    CHECK_THROWS_AS(generateUserToken("trustchainID", "", "userId"_uid),
                    std::invalid_argument);
  }
  SUBCASE("should generate a UserToken")
  {
    auto const userTokenString =
        generateUserToken(trustchainIdString, privateKeyString, "alice"_uid);
    auto const clearStr = base64::decode(userTokenString);
    CHECK_NOTHROW(nlohmann::json::parse(clearStr).get<UserToken>());
  }
  SUBCASE("Should return a base64 string")
  {
    auto const userToken2 = generateUserToken(
        trustchainIdString, privateKeyString, Tanker::SUserId{userIdString});
    CHECK_NOTHROW(base64::decode(userToken2));
  }
  SUBCASE("should be json format")
  {
    auto const userToken2 = generateUserToken(
        trustchainIdString, privateKeyString, Tanker::SUserId{userIdString});
    auto const clearStr = base64::decode(userToken2);
    CHECK_NOTHROW(nlohmann::json::parse(clearStr));
  }
  SUBCASE("should be able to be deserialize in Identity")
  {
    auto const userTokenString = generateUserToken(
        trustchainIdString, privateKeyString, Tanker::SUserId{userIdString});
    auto const clearStr = base64::decode(userTokenString);
    CHECK_NOTHROW(nlohmann::json::parse(clearStr).get<UserToken>());
  }
  SUBCASE("user secret have good format")
  {
    auto const userTokenString =
        generateUserToken(trustchainIdString, privateKeyString, "alice"_uid);
    auto const clearStr = base64::decode<std::string>(userTokenString);
    auto const userToken2 = nlohmann::json::parse(clearStr).get<UserToken>();

    CHECK_NOTHROW(checkUserSecret(userToken2.userSecret,
                                  obfuscateUserId("alice"_uid, trustchainId)));
  }
}

TEST_CASE("generateUserSecret can be checked")
{
  CHECK_NOTHROW(checkUserSecret(generateUserSecret(userId), userId));
}

TEST_CASE("userSecretHash")
{
  SUBCASE("crash when bad args")
  {
    CHECK_THROWS_AS(
        userSecretHash(gsl::make_span(std::vector<uint8_t>()), userId),
        std::invalid_argument);
  }
}

TEST_CASE("User Token")
{
  SUBCASE("We can construct one user token from a good string")
  {
    auto const jsonTok = nlohmann::json::parse(base64::decode(GOOD_USER_TOKEN));
    auto const userToken = jsonTok.get<UserToken>();

    CHECK(userToken.delegation.ephemeralKeyPair.publicKey == publicKey);
    CHECK(userToken.delegation.ephemeralKeyPair.privateKey == privateKey);
    CHECK(userToken.delegation.userId == userId);
    CHECK(userToken.delegation.signature == signature);
    CHECK(userToken.userSecret == userSecret);
  }

  SUBCASE("We can get back the same string from the UserToken")
  {
    UserToken const token{{{publicKey, privateKey}, userId, signature},
                          userSecret};
    auto const tokenString = base64::encode(nlohmann::json(token).dump());

    auto const jsonTok = nlohmann::json::parse(base64::decode(GOOD_USER_TOKEN));
    auto const userToken = jsonTok.get<UserToken>();

    CHECK(token == userToken);
  }
}
}
}
