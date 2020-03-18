#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Identity/Errors/Errc.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/PublicProvisionalIdentity.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>
#include <Tanker/Identity/UserToken.hpp>
#include <Tanker/Identity/Utils.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <Helpers/Errors.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <doctest.h>
#include <gsl-lite.hpp>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <stdexcept>
#include <string>

using namespace Tanker;
using namespace Tanker::Identity;
using Tanker::Trustchain::UserId;
using namespace std::string_literals;
using namespace type_literals;

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
    cppcodec::base64_rfc4648::decode<Trustchain::TrustchainId>(
        trustchainIdString);
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

auto const appSignatureKeyPair = Crypto::SignatureKeyPair{
    cppcodec::base64_rfc4648::decode<Tanker::Crypto::PublicSignatureKey>(
        "W7QEQBu9FXcXIpOgq62tPwBiyFAbpT1rAruD0h/NrTA="),
    cppcodec::base64_rfc4648::decode<Tanker::Crypto::PrivateSignatureKey>(
        "UmnYuvdTaLYG0a+JaDpY6ojw4/2Ll8zsmramVC4fuqRbtARAG70Vdxcik6Crra0/"
        "AGLIUBulPWsCu4PSH82tMA=="),
};
auto const appEncryptionKeyPair = Crypto::EncryptionKeyPair{
    cppcodec::base64_rfc4648::decode<Tanker::Crypto::PublicEncryptionKey>(
        "4QB5TWmvcBrgeyDDLhULINU6tbqAOEQ8v9pjDkPcybA="),
    cppcodec::base64_rfc4648::decode<Tanker::Crypto::PrivateEncryptionKey>(
        "/2j4dI3r8PlvCN3uW4HhA5wBtMKOcACd38K6N0q+mFU="),
};

auto const ephemeralKeyPair =
    Crypto::SignatureKeyPair{publicEphemeralKey, privateEphemeralKey};

auto const delegation =
    Delegation{ephemeralKeyPair, obfuscatedUserId, delegation_signature};

auto const GOOD_SECRET_PROVISIONAL_IDENTITY =
    "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaH"
    "JDTGpkND0iLCJ0YXJnZXQiOiJlbWFpbCIsInZhbHVlIjoiYnJlbmRhbi5laWNoQHRhbmtlci5p"
    "byIsInB1YmxpY19lbmNyeXB0aW9uX2tleSI6Ii8yajRkSTNyOFBsdkNOM3VXNEhoQTV3QnRNS0"
    "9jQUNkMzhLNk4wcSttRlU9IiwicHJpdmF0ZV9lbmNyeXB0aW9uX2tleSI6IjRRQjVUV212Y0Jy"
    "Z2V5RERMaFVMSU5VNnRicUFPRVE4djlwakRrUGN5YkE9IiwicHVibGljX3NpZ25hdHVyZV9rZX"
    "kiOiJXN1FFUUJ1OUZYY1hJcE9ncTYydFB3Qml5RkFicFQxckFydUQwaC9OclRBPSIsInByaXZh"
    "dGVfc2lnbmF0dXJlX2tleSI6IlVtbll1dmRUYUxZRzBhK0phRHBZNm9qdzQvMkxsOHpzbXJhbV"
    "ZDNGZ1cVJidEFSQUc3MFZkeGNpazZDcnJhMC9BR0xJVUJ1bFBXc0N1NFBTSDgydE1BPT0ifQ="
    "="s;
auto const GOOD_PUBLIC_PROVISIONAL_IDENTITY =
    "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaH"
    "JDTGpkND0iLCJ0YXJnZXQiOiJlbWFpbCIsInZhbHVlIjoiYnJlbmRhbi5laWNoQHRhbmtlci5p"
    "byIsInB1YmxpY19lbmNyeXB0aW9uX2tleSI6Ii8yajRkSTNyOFBsdkNOM3VXNEhoQTV3QnRNS0"
    "9jQUNkMzhLNk4wcSttRlU9IiwicHVibGljX3NpZ25hdHVyZV9rZXkiOiJXN1FFUUJ1OUZYY1hJ"
    "cE9ncTYydFB3Qml5RkFicFQxckFydUQwaC9OclRBPSJ9"s;

auto const userEmail = "brendan.eich@tanker.io";

auto const appSignaturePublicKey =
    cppcodec::base64_rfc4648::decode<Tanker::Crypto::PublicSignatureKey>(
        "W7QEQBu9FXcXIpOgq62tPwBiyFAbpT1rAruD0h/NrTA=");
auto const appSignaturePrivateKey =
    cppcodec::base64_rfc4648::decode<Tanker::Crypto::PrivateSignatureKey>(
        "UmnYuvdTaLYG0a+JaDpY6ojw4/2Ll8zsmramVC4fuqRbtARAG70Vdxcik6Crra0/"
        "AGLIUBulPWsCu4PSH82tMA==");
auto const appEncryptionPublicKey =
    cppcodec::base64_rfc4648::decode<Tanker::Crypto::PublicEncryptionKey>(
        "/2j4dI3r8PlvCN3uW4HhA5wBtMKOcACd38K6N0q+mFU=");
auto const appEncryptionPrivateKey =
    cppcodec::base64_rfc4648::decode<Tanker::Crypto::PrivateEncryptionKey>(
        "4QB5TWmvcBrgeyDDLhULINU6tbqAOEQ8v9pjDkPcybA=");

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
    TANKER_CHECK_THROWS_WITH_CODE(
        createIdentity("trustchainID", "privateKey", ""_uid),
        Errc::InvalidUserId);
  }

  TEST_CASE("should throw given empty trustchainId")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        createIdentity("", "privateKey", "userId"_uid),
        Errc::InvalidTrustchainId);
  }

  TEST_CASE("should throw given empty privateKey")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        createIdentity("trustchainId", "", "userId"_uid),
        Errc::InvalidTrustchainPrivateKey);
  }

  TEST_CASE("We can create an identity from strings")
  {
    CHECK_NOTHROW(createIdentity(
        trustchainIdString, trustchainPrivateKeyString, suserId));
  }
}

TEST_SUITE("generate provisional Identity")
{
  TEST_CASE("should throw given empty trustchainId")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        createProvisionalIdentity("", Email{userEmail}),
        Errc::InvalidTrustchainId);
  }

  TEST_CASE("should throw given empty email")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        createProvisionalIdentity("trustchainId", Email{""}),
        Errc::InvalidEmail);
  }

  TEST_CASE("We can create a provisional identity from strings")
  {
    CHECK_NOTHROW(
        createProvisionalIdentity(trustchainIdString, Email{userEmail}));
  }
}

TEST_SUITE("serialization")
{
  TEST_CASE("We can deserialize a secret permanent identity from a good string")
  {
    auto const identity =
        extract<SecretPermanentIdentity>(GOOD_SECRET_PERMANENT_IDENTITY);
    CHECK_EQ(identity.trustchainId, trustchainId);
    CHECK_EQ(identity.delegation, delegation);
    CHECK_EQ(identity.userSecret, userSecret);
  }

  TEST_CASE("We can deserialize a public permanent identity from a good string")
  {
    auto const publicIdentity =
        extract<PublicIdentity>(GOOD_PUBLIC_PERMANENT_IDENTITY);
    auto const publicPermanentIdentity =
        boost::variant2::get<PublicPermanentIdentity>(publicIdentity);
    CHECK_EQ(publicPermanentIdentity.trustchainId, trustchainId);
    CHECK_EQ(publicPermanentIdentity.userId, obfuscatedUserId);
  }

  TEST_CASE(
      "We cannot deserialize a secret permanent identity as a public permanent "
      "identity")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        extract<PublicPermanentIdentity>(GOOD_SECRET_PERMANENT_IDENTITY),
        Errc::InvalidType);
  }

  TEST_CASE(
      "We can deserialize a secret provisional identity from a good string")
  {
    auto const identity =
        extract<SecretProvisionalIdentity>(GOOD_SECRET_PROVISIONAL_IDENTITY);

    CHECK_EQ(identity.trustchainId, trustchainId);
    CHECK_EQ(identity.value, userEmail);
    CHECK_EQ(identity.target, TargetType::Email);
    CHECK_EQ(identity.appSignatureKeyPair.publicKey, appSignaturePublicKey);
    CHECK_EQ(identity.appSignatureKeyPair.privateKey, appSignaturePrivateKey);
    CHECK_EQ(identity.appEncryptionKeyPair.publicKey, appEncryptionPublicKey);
    CHECK_EQ(identity.appEncryptionKeyPair.privateKey, appEncryptionPrivateKey);
  }

  TEST_CASE(
      "We can deserialize a public provisional identity from a good string")
  {
    auto const identity =
        extract<PublicProvisionalIdentity>(GOOD_PUBLIC_PROVISIONAL_IDENTITY);

    CHECK_EQ(identity.trustchainId, trustchainId);
    CHECK_EQ(identity.value, userEmail);
    CHECK_EQ(identity.target, TargetType::Email);
    CHECK_EQ(identity.appSignaturePublicKey, appSignaturePublicKey);
    CHECK_EQ(identity.appEncryptionPublicKey, appEncryptionPublicKey);
  }

  TEST_CASE(
      "We cannot deserialize a secret provisional identity as a public "
      "provisional identity")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        extract<PublicProvisionalIdentity>(GOOD_SECRET_PROVISIONAL_IDENTITY),
        Errc::InvalidType);
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
    TANKER_CHECK_THROWS_WITH_CODE(
        upgradeUserToken(trustchainIdString, "herbert"_uid, GOOD_USER_TOKEN),
        Errc::InvalidUserId);
  }
}

TEST_SUITE("getPublicIdentity")
{
  TEST_CASE("get a public identity from a secret permanent identity")
  {
    auto const identityStr = createIdentity(
        trustchainIdString, trustchainPrivateKeyString, "alice"_uid);
    auto const publicIdentityStr = getPublicIdentity(identityStr);
    auto const publicIdentity = extract<PublicIdentity>(publicIdentityStr);
    auto const aliceO = obfuscateUserId("alice"_uid, trustchainId);
    auto const p =
        boost::variant2::get_if<PublicPermanentIdentity>(&publicIdentity);
    REQUIRE_UNARY(p);
    CHECK_EQ(p->trustchainId, trustchainId);
    CHECK_EQ(p->userId, aliceO);
  }

  TEST_CASE("get a public identity from a secret provisional identity")
  {
    auto const b64PublicIdentity =
        getPublicIdentity(GOOD_SECRET_PROVISIONAL_IDENTITY);
    auto const publicIdentity = extract<PublicIdentity>(b64PublicIdentity);
    auto const p =
        boost::variant2::get_if<PublicProvisionalIdentity>(&publicIdentity);

    REQUIRE_UNARY(p);
    CHECK_EQ(p->trustchainId, trustchainId);
    CHECK_EQ(p->target, TargetType::Email);
    CHECK_EQ(p->value, userEmail);
    CHECK_EQ(p->appSignaturePublicKey, appSignaturePublicKey);
    CHECK_EQ(p->appEncryptionPublicKey, appEncryptionPublicKey);
  }
}

TEST_SUITE("Generate user token")
{
  TEST_CASE("should throw given empty userId")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        generateUserToken("trustchainID", "privateKey", ""_uid),
        Errc::InvalidUserId);
  }

  TEST_CASE("should throw given empty trustchainId")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        generateUserToken("", "privateKey", "userId"_uid),
        Errc::InvalidTrustchainId);
  }

  TEST_CASE("should throw given empty privateKey")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        generateUserToken("trustchainId", "", "userId"_uid),
        Errc::InvalidTrustchainPrivateKey);
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

  TEST_CASE("extract should throw when identity has invalid format")
  {
    SUBCASE("json")
    {
      auto const invalidIdentity = cppcodec::base64_rfc4648::encode("}");
      TANKER_CHECK_THROWS_WITH_CODE(extract<UserToken>(invalidIdentity),
                                    Errc::InvalidFormat);
    }

    SUBCASE("base64")
    {
      TANKER_CHECK_THROWS_WITH_CODE(extract<UserToken>("?"),
                                    Errc::InvalidFormat);
    }
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
