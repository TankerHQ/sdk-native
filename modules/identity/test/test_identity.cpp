#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Identity/UserToken.hpp>
#include <Tanker/Identity/Utils.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <doctest.h>
#include <fmt/format.h>
#include <gsl-lite.hpp>
#include <nlohmann/json.hpp>

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

using Tanker::Trustchain::UserId;
using namespace std::string_literals;
namespace Tanker
{
using namespace type_literals;
namespace Identity
{
namespace
{
auto const GOOD_USER_TOKEN =
    "eyJkZWxlZ2F0aW9uX3NpZ25hdHVyZSI6IlU5V1FvbEN2UnlqVDhvUjJQUW1kMVdYTkNpMHFtTD"
    "EyaE5ydEdhYllSRVdpcnk1MmtXeDFBZ1l6a0x4SDZncG8zTWlBOXIrK3pobm1vWWRFSjArSkN3"
    "PT0iLCJlcGhlbWVyYWxfcHJpdmF0ZV9zaWduYXR1cmVfa2V5IjoiakVEVDR3UUNjMURGd29kWE"
    "5QSEZDbG5kVFBuRnVGbVhoQnQraXNLVTRacGVIZUxURU5PbXZjZGUwSFpEblh0QXEvZHJNM05j"
    "c3RjeDBrTk5JZmh0M2c9PSIsImVwaGVtZXJhbF9wdWJsaWNfc2lnbmF0dXJlX2tleSI6IlhoM2"
    "kweERUcHIzSFh0QjJRNTE3UUt2M2F6TnpYTExYTWRKRFRTSDRiZDQ9IiwidXNlcl9pZCI6IlJE"
    "YTBlcTRYTnVqNXRWN2hkYXBqT3hobWhlVGg0UUJETnB5NFN2eTlYb2s9IiwidXNlcl9zZWNyZX"
    "QiOiI3RlNmL24wZTc2UVQzczBEa3ZldFJWVkpoWFpHRWpPeGo1RVdBRmV4dmpJPSJ9"s;

auto const GOOD_SECRET_PERMANENT_IDENTITY =
    "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaH"
    "JDTGpkND0iLCJ0YXJnZXQiOiJ1c2VyIiwidmFsdWUiOiJSRGEwZXE0WE51ajV0VjdoZGFwak94"
    "aG1oZVRoNFFCRE5weTRTdnk5WG9rPSIsImRlbGVnYXRpb25fc2lnbmF0dXJlIjoiVTlXUW9sQ3"
    "ZSeWpUOG9SMlBRbWQxV1hOQ2kwcW1MMTJoTnJ0R2FiWVJFV2lyeTUya1d4MUFnWXprTHhINmdw"
    "bzNNaUE5cisremhubW9ZZEVKMCtKQ3c9PSIsImVwaGVtZXJhbF9wdWJsaWNfc2lnbmF0dXJlX2"
    "tleSI6IlhoM2kweERUcHIzSFh0QjJRNTE3UUt2M2F6TnpYTExYTWRKRFRTSDRiZDQ9IiwiZXBo"
    "ZW1lcmFsX3ByaXZhdGVfc2lnbmF0dXJlX2tleSI6ImpFRFQ0d1FDYzFERndvZFhOUEhGQ2xuZF"
    "RQbkZ1Rm1YaEJ0K2lzS1U0WnBlSGVMVEVOT212Y2RlMEhaRG5YdEFxL2RyTTNOY3N0Y3gwa05O"
    "SWZodDNnPT0iLCJ1c2VyX3NlY3JldCI6IjdGU2YvbjBlNzZRVDNzMERrdmV0UlZWSmhYWkdFak"
    "94ajVFV0FGZXh2akk9In0="s;

auto const GOOD_PUBLIC_PERMANENT_IDENTITY =
    "eyJ0YXJnZXQiOiJ1c2VyIiwidHJ1c3RjaGFpbl9pZCI6InRwb3h5TnpoMGhVOUcyaTlhZ012SH"
    "l5ZCtwTzZ6R0NqTzlCZmhyQ0xqZDQ9IiwidmFsdWUiOiJSRGEwZXE0WE51ajV0VjdoZGFwak94"
    "aG1oZVRoNFFCRE5weTRTdnk5WG9rPSJ9"s;

auto const trustchainIdString = "tpoxyNzh0hU9G2i9agMvHyyd+pO6zGCjO9BfhrCLjd4="s;
auto const trustchainPrivateKeyString =
    "cTMoGGUKhwN47ypq4xAXAtVkNWeyUtMltQnYwJhxWYSvqjPVGmXd2wwa7y17QtPTZhn8bxb015"
    "CZC/e4ZI7+MQ=="s;

auto const trustchainId =
    cppcodec::base64_rfc4648::decode<TrustchainId>(trustchainIdString);
auto const trustchainPrivateKey =
    cppcodec::base64_rfc4648::decode<Tanker::Crypto::PrivateSignatureKey>(
        trustchainPrivateKeyString);

auto const suserId = "b_eich"_uid;
auto const obfuscatedUserId = obfuscateUserId(suserId, trustchainId);

auto const userSecret =
    cppcodec::base64_rfc4648::decode<Tanker::Crypto::SymmetricKey>(
        "7FSf/n0e76QT3s0DkvetRVVJhXZGEjOxj5EWAFexvjI=");

auto const publicEphemeralKey =
    cppcodec::base64_rfc4648::decode<Tanker::Crypto::PublicSignatureKey>(
        "Xh3i0xDTpr3HXtB2Q517QKv3azNzXLLXMdJDTSH4bd4=");
auto const privateEphemeralKey =
    cppcodec::base64_rfc4648::decode<Tanker::Crypto::PrivateSignatureKey>(
        "jEDT4wQCc1DFwodXNPHFClndTPnFuFmXhBt+isKU4ZpeHeLTENOmvcde0HZDnXtAq/"
        "drM3Ncstcx0kNNIfht3g==");
auto const delegation_signature = cppcodec::base64_rfc4648::decode<
    Tanker::Crypto::Signature>(
    "U9WQolCvRyjT8oR2PQmd1WXNCi0qmL12hNrtGabYREWiry52kWx1AgYzkLxH6gpo3MiA9r++"
    "zhnmoYdEJ0+JCw==");

auto const ephemeralKeyPair =
    Crypto::SignatureKeyPair{publicEphemeralKey, privateEphemeralKey};

auto const delegation =
    Delegation{ephemeralKeyPair, obfuscatedUserId, delegation_signature};

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
  CHECK_NOTHROW(checkUserSecret(userSecret, obfuscatedUserId));
}

TEST_SUITE("generate Identity")
{
  TEST_CASE("should throw given empty userId")
  {
    CHECK_THROWS_AS(createIdentity("trustchainID", "privateKey", ""_uid),
                    std::invalid_argument);
  }
  TEST_CASE("should throw given empty trustchainId")
  {
    CHECK_THROWS_AS(createIdentity("", "privateKey", "userId"_uid),
                    std::invalid_argument);
  }
  TEST_CASE("should throw given empty privateKey")
  {
    CHECK_THROWS_AS(createIdentity("trustchainID", "", "userId"_uid),
                    std::invalid_argument);
  }
  TEST_CASE("We can create an identity from strings")
  {
    CHECK_NOTHROW(createIdentity(
        trustchainIdString, trustchainPrivateKeyString, suserId));
  }
  TEST_CASE("We can deserialize an identity from a good string")
  {
    auto const identity =
        extract<SecretPermanentIdentity>(GOOD_SECRET_PERMANENT_IDENTITY);
    CHECK_EQ(identity.trustchainId, trustchainId);
    CHECK_EQ(identity.delegation, delegation);
    CHECK_EQ(identity.userSecret, userSecret);
  }
  TEST_CASE("We can deserialize a public identity from a good string")
  {
    auto const publicIdentity =
        extract<PublicIdentity>(GOOD_PUBLIC_PERMANENT_IDENTITY);
    auto const publicPermanentIdentity =
        mpark::get<PublicPermanentIdentity>(publicIdentity);
    CHECK_EQ(publicPermanentIdentity.trustchainId, trustchainId);
    CHECK_EQ(publicPermanentIdentity.userId, obfuscatedUserId);
  }
}

TEST_SUITE("ugprade a user token to an identity")
{
  TEST_CASE("We can upgrade a userToken to an identity")
  {
    auto identity = extract<SecretPermanentIdentity>(
        upgradeUserToken(trustchainIdString, suserId, GOOD_USER_TOKEN));
    CHECK_EQ(identity.trustchainId, trustchainId);
    CHECK_EQ(identity.delegation, delegation);
    CHECK_EQ(identity.userSecret, userSecret);
  }
  TEST_CASE("should throw when upgrading the wrong userId")
  {
    CHECK_THROWS_AS(
        upgradeUserToken(trustchainIdString, "herbert"_uid, GOOD_USER_TOKEN),
        std::invalid_argument);
  }
}

TEST_CASE("get a public identity from a secret permanent identity")
{
  auto const identityStr = createIdentity(
      trustchainIdString, trustchainPrivateKeyString, "alice"_uid);
  auto const publicIdentityStr = getPublicIdentity(identityStr);
  auto const publicIdentity = extract<PublicIdentity>(publicIdentityStr);
  auto const aliceO = obfuscateUserId("alice"_uid, trustchainId);
  auto* p = mpark::get_if<PublicPermanentIdentity>(&publicIdentity);
  CHECK_UNARY(p);
  CHECK_EQ(p->trustchainId, trustchainId);
  CHECK_EQ(p->userId, aliceO);
}

TEST_SUITE("Generate user token")
{
  TEST_CASE("should throw given empty userId")
  {
    CHECK_THROWS_AS(generateUserToken("trustchainID", "privateKey", ""_uid),
                    std::invalid_argument);
  }
  TEST_CASE("should throw given empty trustchainId")
  {
    CHECK_THROWS_AS(generateUserToken("", "privateKey", "userId"_uid),
                    std::invalid_argument);
  }
  TEST_CASE("should throw given empty privateKey")
  {
    CHECK_THROWS_AS(generateUserToken("trustchainID", "", "userId"_uid),
                    std::invalid_argument);
  }
  TEST_CASE("should generate a UserToken")
  {
    CHECK_NOTHROW(generateUserToken(
        trustchainIdString, trustchainPrivateKeyString, "alice"_uid));
  }
  TEST_CASE("should be able to be deserialize a user token")
  {
    auto const userTokenString = generateUserToken(
        trustchainIdString, trustchainPrivateKeyString, suserId);
    auto const clearStr = cppcodec::base64_rfc4648::decode(userTokenString);
    CHECK_NOTHROW(nlohmann::json::parse(clearStr).get<UserToken>());
  }
  TEST_CASE("user secret have good format")
  {
    auto const userTokenString = generateUserToken(
        trustchainIdString, trustchainPrivateKeyString, "alice"_uid);
    auto const userToken2 = extract<UserToken>(userTokenString);

    CHECK_NOTHROW(checkUserSecret(userToken2.userSecret,
                                  obfuscateUserId("alice"_uid, trustchainId)));
  }
  TEST_CASE("We can construct one user token from a good string")
  {
    auto const userToken = extract<UserToken>(GOOD_USER_TOKEN);

    CHECK_EQ(userToken.delegation, delegation);
    CHECK_EQ(userToken.userSecret, userSecret);
    CHECK_NOTHROW(checkUserSecret(userToken.userSecret,
                                  obfuscateUserId(suserId, trustchainId)));
  }
}

TEST_CASE("generateUserSecret can be checked")
{
  CHECK_NOTHROW(
      checkUserSecret(generateUserSecret(obfuscatedUserId), obfuscatedUserId));
}

TEST_SUITE("userSecretHash")
{
  TEST_CASE("crash when bad args")
  {
    CHECK_THROWS_AS(userSecretHash(gsl::make_span(std::vector<uint8_t>()),
                                   obfuscatedUserId),
                    std::invalid_argument);
  }
}
}
}
