#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Identity/Errors/Errc.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/PublicProvisionalIdentity.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>
#include <Tanker/Identity/Utils.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <Helpers/Email.hpp>
#include <Helpers/Errors.hpp>

#include <catch2/catch.hpp>
#include <gsl/gsl-lite.hpp>
#include <mgs/base64.hpp>
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
    "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaH"
    "JDTGpkND0iLCJ0YXJnZXQiOiJ1c2VyIiwidmFsdWUiOiJSRGEwZXE0WE51ajV0VjdoZGFwak94"
    "aG1oZVRoNFFCRE5weTRTdnk5WG9rPSJ9"s;

auto const trustchainIdString = "tpoxyNzh0hU9G2i9agMvHyyd+pO6zGCjO9BfhrCLjd4="s;
auto const trustchainPrivateKeyString =
    "cTMoGGUKhwN47ypq4xAXAtVkNWeyUtMltQnYwJhxWYSvqjPVGmXd2wwa7y17QtPTZhn8bxb015"
    "CZC/e4ZI7+MQ=="s;

auto const trustchainId =
    mgs::base64::decode<Trustchain::TrustchainId>(trustchainIdString);
auto const trustchainPrivateKey =
    mgs::base64::decode<Tanker::Crypto::PrivateSignatureKey>(
        trustchainPrivateKeyString);

auto const suserId = "b_eich"_uid;
auto const obfuscatedUserId = obfuscateUserId(suserId, trustchainId);

auto const userSecret = mgs::base64::decode<Tanker::Crypto::SymmetricKey>(
    "7FSf/n0e76QT3s0DkvetRVVJhXZGEjOxj5EWAFexvjI=");

auto const publicEphemeralKey =
    mgs::base64::decode<Tanker::Crypto::PublicSignatureKey>(
        "Xh3i0xDTpr3HXtB2Q517QKv3azNzXLLXMdJDTSH4bd4=");
auto const privateEphemeralKey =
    mgs::base64::decode<Tanker::Crypto::PrivateSignatureKey>(
        "jEDT4wQCc1DFwodXNPHFClndTPnFuFmXhBt+isKU4ZpeHeLTENOmvcde0HZDnXtAq/"
        "drM3Ncstcx0kNNIfht3g==");
auto const delegation_signature = mgs::base64::decode<
    Tanker::Crypto::Signature>(
    "U9WQolCvRyjT8oR2PQmd1WXNCi0qmL12hNrtGabYREWiry52kWx1AgYzkLxH6gpo3MiA9r++"
    "zhnmoYdEJ0+JCw==");

auto const appSignatureKeyPair = Crypto::SignatureKeyPair{
    mgs::base64::decode<Tanker::Crypto::PublicSignatureKey>(
        "W7QEQBu9FXcXIpOgq62tPwBiyFAbpT1rAruD0h/NrTA="),
    mgs::base64::decode<Tanker::Crypto::PrivateSignatureKey>(
        "UmnYuvdTaLYG0a+JaDpY6ojw4/2Ll8zsmramVC4fuqRbtARAG70Vdxcik6Crra0/"
        "AGLIUBulPWsCu4PSH82tMA=="),
};
auto const appEncryptionKeyPair = Crypto::EncryptionKeyPair{
    mgs::base64::decode<Tanker::Crypto::PublicEncryptionKey>(
        "4QB5TWmvcBrgeyDDLhULINU6tbqAOEQ8v9pjDkPcybA="),
    mgs::base64::decode<Tanker::Crypto::PrivateEncryptionKey>(
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
auto const GOOD_OLD_PUBLIC_PROVISIONAL_IDENTITY =
    "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaH"
    "JDTGpkND0iLCJ0YXJnZXQiOiJlbWFpbCIsInZhbHVlIjoiYnJlbmRhbi5laWNoQHRhbmtlci5p"
    "byIsInB1YmxpY19lbmNyeXB0aW9uX2tleSI6Ii8yajRkSTNyOFBsdkNOM3VXNEhoQTV3QnRNS0"
    "9jQUNkMzhLNk4wcSttRlU9IiwicHVibGljX3NpZ25hdHVyZV9rZXkiOiJXN1FFUUJ1OUZYY1hJ"
    "cE9ncTYydFB3Qml5RkFicFQxckFydUQwaC9OclRBPSJ9"s;

auto const GOOD_PUBLIC_PROVISIONAL_IDENTITY =
    "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaH"
    "JDTGpkND0iLCJ0YXJnZXQiOiJoYXNoZWRfZW1haWwiLCJ2YWx1ZSI6IjB1MmM4dzhFSVpXVDJG"
    "elJOL3l5TTVxSWJFR1lUTkRUNVNrV1ZCdTIwUW89IiwicHVibGljX2VuY3J5cHRpb25fa2V5Ij"
    "oiLzJqNGRJM3I4UGx2Q04zdVc0SGhBNXdCdE1LT2NBQ2QzOEs2TjBxK21GVT0iLCJwdWJsaWNf"
    "c2lnbmF0dXJlX2tleSI6Ilc3UUVRQnU5RlhjWElwT2dxNjJ0UHdCaXlGQWJwVDFyQXJ1RDBoL0"
    "5yVEE9In0="s;

auto const GOOD_SECRET_PHONE_NUMBER_PROVISIONAL_IDENTITY =
    "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaH"
    "JDTGpkND0iLCJ0YXJnZXQiOiJwaG9uZV9udW1iZXIiLCJ2YWx1ZSI6IiszMzYzOTk4MjIzMyIs"
    "InB1YmxpY19lbmNyeXB0aW9uX2tleSI6IjAweWRuY2QxTHZKR0NrWWw5L1JzNUFDTGx2RGNhem"
    "o3RWc3NXo0OTRRWFU9IiwicHJpdmF0ZV9lbmNyeXB0aW9uX2tleSI6IlNyRHJjRS9Nbkx4WHFr"
    "WlJIenJYb2FJSUNKb3hUR0htUWduUjllU090UU09IiwicHVibGljX3NpZ25hdHVyZV9rZXkiOi"
    "I2SG95eitrMmdqcnJwUDZxZnpRZEJDaXl6R0V5ajBWNWx6Mm9VUlVrRERNPSIsInByaXZhdGVf"
    "c2lnbmF0dXJlX2tleSI6IlJqQzRrTnlFL3EyQU5wbUpCN3h5UHpudkV0Z3Z2YTloMHU5dlRYQW"
    "N4Q2pvZWpMUDZUYUNPdXVrL3FwL05CMEVLTExNWVRLUFJYbVhQYWhSRlNRTU13PT0ifQ=="s;

auto const GOOD_PUBLIC_PHONE_NUMBER_PROVISIONAL_IDENTITY =
    "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaH"
    "JDTGpkND0iLCJ0YXJnZXQiOiJoYXNoZWRfcGhvbmVfbnVtYmVyIiwidmFsdWUiOiJTbXRYZHdN"
    "RUFCYzl4OFBCNVJQT2lqanVWYlNHR3N4N2xUODNhN2dSMVhFPSIsInB1YmxpY19lbmNyeXB0aW"
    "9uX2tleSI6IjAweWRuY2QxTHZKR0NrWWw5L1JzNUFDTGx2RGNhemo3RWc3NXo0OTRRWFU9Iiwi"
    "cHVibGljX3NpZ25hdHVyZV9rZXkiOiI2SG95eitrMmdqcnJwUDZxZnpRZEJDaXl6R0V5ajBWNW"
    "x6Mm9VUlVrRERNPSJ9"s;

auto const userEmail = "brendan.eich@tanker.io"s;
auto const phoneNumber = "+33639982233"s;
auto const b64HashedEmail = mgs::base64::encode(Crypto::generichash(
    gsl::make_span(std::string(userEmail)).as_span<uint8_t const>()));

auto const appSignaturePublicKey =
    mgs::base64::decode<Tanker::Crypto::PublicSignatureKey>(
        "W7QEQBu9FXcXIpOgq62tPwBiyFAbpT1rAruD0h/NrTA=");
auto const appSignaturePrivateKey =
    mgs::base64::decode<Tanker::Crypto::PrivateSignatureKey>(
        "UmnYuvdTaLYG0a+JaDpY6ojw4/2Ll8zsmramVC4fuqRbtARAG70Vdxcik6Crra0/"
        "AGLIUBulPWsCu4PSH82tMA==");
auto const appEncryptionPublicKey =
    mgs::base64::decode<Tanker::Crypto::PublicEncryptionKey>(
        "/2j4dI3r8PlvCN3uW4HhA5wBtMKOcACd38K6N0q+mFU=");
auto const appEncryptionPrivateKey =
    mgs::base64::decode<Tanker::Crypto::PrivateEncryptionKey>(
        "4QB5TWmvcBrgeyDDLhULINU6tbqAOEQ8v9pjDkPcybA=");

auto const phoneNumberAppSignaturePublicKey =
    mgs::base64::decode<Tanker::Crypto::PublicSignatureKey>(
        "6Hoyz+k2gjrrpP6qfzQdBCiyzGEyj0V5lz2oURUkDDM=");
auto const phoneNumberAppSignaturePrivateKey =
    mgs::base64::decode<Tanker::Crypto::PrivateSignatureKey>(
        "RjC4kNyE/q2ANpmJB7xyPznvEtgvva9h0u9vTXAcxCjoejLP6TaCOuuk/qp/"
        "NB0EKLLMYTKPRXmXPahRFSQMMw==");
auto const phoneNumberAppEncryptionPublicKey =
    mgs::base64::decode<Tanker::Crypto::PublicEncryptionKey>(
        "00ydncd1LvJGCkYl9/Rs5ACLlvDcazj7Eg75z494QXU=");
auto const phoneNumberAppEncryptionPrivateKey =
    mgs::base64::decode<Tanker::Crypto::PrivateEncryptionKey>(
        "SrDrcE/MnLxXqkZRHzrXoaIICJoxTGHmQgnR9eSOtQM=");

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

PublicIdentity createTestPermanentIdentity(
    Trustchain::TrustchainId const& trustchainId,
    Crypto::PrivateSignatureKey const& trustchainPrivateKey)
{
  Trustchain::UserId userId;
  Crypto::randomFill(userId);

  auto identity = createIdentity(trustchainId, trustchainPrivateKey, userId);
  return Identity::getPublicIdentity(identity);
}

PublicIdentity createTestProvisionalIdentity(
    Trustchain::TrustchainId const& trustchainId)
{
  Trustchain::UserId userId;
  Crypto::randomFill(userId);
  auto const email = makeEmail();

  auto identity =
      Tanker::Identity::createProvisionalIdentity(trustchainId, email);
  return Identity::getPublicIdentity(identity);
}
}

TEST_CASE("checkUserSecret")
{
  CHECK_NOTHROW(checkUserSecret(userSecret, obfuscatedUserId));
}

TEST_CASE("generate Identity")
{
  SECTION("should throw given empty userId")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        createIdentity("trustchainID", "privateKey", ""_uid),
        Errc::InvalidUserId);
  }

  SECTION("should throw given empty trustchainId")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        createIdentity("", "privateKey", "userId"_uid),
        Errc::InvalidTrustchainId);
  }

  SECTION("should throw given empty privateKey")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        createIdentity("trustchainId", "", "userId"_uid),
        Errc::InvalidTrustchainPrivateKey);
  }

  SECTION("We can create an identity from strings")
  {
    CHECK_NOTHROW(createIdentity(
        trustchainIdString, trustchainPrivateKeyString, suserId));
  }
}

TEST_CASE("generate provisional Identity")
{
  SECTION("should throw given empty trustchainId")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        createProvisionalIdentity("", Email{userEmail}),
        Errc::InvalidTrustchainId);
  }

  SECTION("should throw given empty email")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        createProvisionalIdentity("trustchainId", Email{""}),
        Errc::InvalidEmail);
  }

  SECTION("We can create a provisional identity from strings")
  {
    CHECK_NOTHROW(
        createProvisionalIdentity(trustchainIdString, Email{userEmail}));
  }
}

TEST_CASE("serialization")
{
  SECTION(
      "We can de/reserialize a secret permanent identity from a good string")
  {
    auto const identity =
        extract<SecretPermanentIdentity>(GOOD_SECRET_PERMANENT_IDENTITY);
    CHECK(identity.trustchainId == trustchainId);
    CHECK(identity.delegation == delegation);
    CHECK(identity.userSecret == userSecret);
    CHECK(to_string(identity) == GOOD_SECRET_PERMANENT_IDENTITY);
  }

  SECTION(
      "We can de/reserialize a public permanent identity from a good string")
  {
    auto const publicIdentity =
        extract<PublicIdentity>(GOOD_PUBLIC_PERMANENT_IDENTITY);
    auto const publicPermanentIdentity =
        boost::variant2::get<PublicPermanentIdentity>(publicIdentity);
    CHECK(publicPermanentIdentity.trustchainId == trustchainId);
    CHECK(publicPermanentIdentity.userId == obfuscatedUserId);
    CHECK(to_string(publicIdentity) == GOOD_PUBLIC_PERMANENT_IDENTITY);
  }

  SECTION(
      "We cannot deserialize a secret permanent identity as a public permanent "
      "identity")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        extract<PublicPermanentIdentity>(GOOD_SECRET_PERMANENT_IDENTITY),
        Errc::InvalidType);
  }

  SECTION(
      "We can de/reserialize an email secret provisional identity from a good "
      "string")
  {
    auto const identity =
        extract<SecretProvisionalIdentity>(GOOD_SECRET_PROVISIONAL_IDENTITY);

    CHECK(identity.trustchainId == trustchainId);
    CHECK(identity.value == userEmail);
    CHECK(identity.target == TargetType::Email);
    CHECK(identity.appSignatureKeyPair.publicKey == appSignaturePublicKey);
    CHECK(identity.appSignatureKeyPair.privateKey == appSignaturePrivateKey);
    CHECK(identity.appEncryptionKeyPair.publicKey == appEncryptionPublicKey);
    CHECK(identity.appEncryptionKeyPair.privateKey == appEncryptionPrivateKey);
    CHECK(to_string(identity) == GOOD_SECRET_PROVISIONAL_IDENTITY);
  }

  SECTION(
      "We can de/reserialize a phone number secret provisional identity from a "
      "good string")
  {
    auto const identity = extract<SecretProvisionalIdentity>(
        GOOD_SECRET_PHONE_NUMBER_PROVISIONAL_IDENTITY);

    CHECK(identity.trustchainId == trustchainId);
    CHECK(identity.value == phoneNumber);
    CHECK(identity.target == TargetType::PhoneNumber);
    CHECK(identity.appSignatureKeyPair.publicKey ==
          phoneNumberAppSignaturePublicKey);
    CHECK(identity.appSignatureKeyPair.privateKey ==
          phoneNumberAppSignaturePrivateKey);
    CHECK(identity.appEncryptionKeyPair.publicKey ==
          phoneNumberAppEncryptionPublicKey);
    CHECK(identity.appEncryptionKeyPair.privateKey ==
          phoneNumberAppEncryptionPrivateKey);
    CHECK(to_string(identity) == GOOD_SECRET_PHONE_NUMBER_PROVISIONAL_IDENTITY);
  }

  SECTION("We can deserialize an unhashed email public provisional identity")
  {
    auto const identity = extract<PublicProvisionalIdentity>(
        GOOD_OLD_PUBLIC_PROVISIONAL_IDENTITY);

    CHECK(identity.trustchainId == trustchainId);
    CHECK(identity.value == userEmail);
    CHECK(identity.target == TargetType::Email);
    CHECK(identity.appSignaturePublicKey == appSignaturePublicKey);
    CHECK(identity.appEncryptionPublicKey == appEncryptionPublicKey);
    CHECK(to_string(identity) == GOOD_OLD_PUBLIC_PROVISIONAL_IDENTITY);
  }

  SECTION("We can deserialize a hashed email public provisional identity")
  {
    auto const identity =
        extract<PublicProvisionalIdentity>(GOOD_PUBLIC_PROVISIONAL_IDENTITY);
    auto hashedEmail = mgs::base64::encode(Crypto::generichash(
        gsl::make_span(userEmail).as_span<std::uint8_t const>()));

    CHECK(identity.trustchainId == trustchainId);
    CHECK(identity.value == hashedEmail);
    CHECK(identity.target == TargetType::HashedEmail);
    CHECK(identity.appSignaturePublicKey == appSignaturePublicKey);
    CHECK(identity.appEncryptionPublicKey == appEncryptionPublicKey);
  }

  SECTION("We can deserialize a phone number public provisional identity")
  {
    auto const identity = extract<PublicProvisionalIdentity>(
        GOOD_PUBLIC_PHONE_NUMBER_PROVISIONAL_IDENTITY);
    auto const salt = Crypto::generichash(phoneNumberAppSignaturePrivateKey);

    std::vector<std::uint8_t> buffer(salt.begin(), salt.end());
    buffer.insert(buffer.end(), phoneNumber.begin(), phoneNumber.end());

    auto const hashedPhoneNumber =
        mgs::base64::encode(Crypto::generichash(buffer));

    CHECK(identity.trustchainId == trustchainId);
    CHECK(identity.value == hashedPhoneNumber);
    CHECK(identity.target == TargetType::HashedPhoneNumber);
    CHECK(identity.appSignaturePublicKey == phoneNumberAppSignaturePublicKey);
    CHECK(identity.appEncryptionPublicKey == phoneNumberAppEncryptionPublicKey);
    CHECK(to_string(identity) == GOOD_PUBLIC_PHONE_NUMBER_PROVISIONAL_IDENTITY);
  }
}

TEST_CASE(
    "We cannot deserialize a secret provisional identity as a public "
    "provisional identity")
{
  TANKER_CHECK_THROWS_WITH_CODE(
      extract<PublicProvisionalIdentity>(GOOD_SECRET_PROVISIONAL_IDENTITY),
      Errc::InvalidType);
}

TEST_CASE("getPublicIdentity")
{
  SECTION("get a public identity from a secret permanent identity")
  {
    auto const identityStr = createIdentity(
        trustchainIdString, trustchainPrivateKeyString, "alice"_uid);
    auto const publicIdentityStr = getPublicIdentity(identityStr);
    auto const publicIdentity = extract<PublicIdentity>(publicIdentityStr);
    auto const aliceO = obfuscateUserId("alice"_uid, trustchainId);
    auto const p =
        boost::variant2::get_if<PublicPermanentIdentity>(&publicIdentity);
    REQUIRE(p);
    CHECK(p->trustchainId == trustchainId);
    CHECK(p->userId == aliceO);
  }

  SECTION("get a public identity from a secret provisional identity")
  {
    auto const b64PublicIdentity =
        getPublicIdentity(GOOD_SECRET_PROVISIONAL_IDENTITY);
    auto const publicIdentity = extract<PublicIdentity>(b64PublicIdentity);
    auto const p =
        boost::variant2::get_if<PublicProvisionalIdentity>(&publicIdentity);

    REQUIRE(p);
    CHECK(p->trustchainId == trustchainId);
    CHECK(p->target == TargetType::HashedEmail);
    CHECK(p->value == b64HashedEmail);
    CHECK(p->appSignaturePublicKey == appSignaturePublicKey);
    CHECK(p->appEncryptionPublicKey == appEncryptionPublicKey);
    CHECK(b64PublicIdentity == GOOD_PUBLIC_PROVISIONAL_IDENTITY);
  }
}

TEST_CASE("generateUserSecret can be checked")
{
  CHECK_NOTHROW(
      checkUserSecret(generateUserSecret(obfuscatedUserId), obfuscatedUserId));
}

TEST_CASE("ensure public identity in trustchain")
{
  SECTION("does not throw with an empty array")
  {
    Trustchain::TrustchainId otherTrustchainId;
    Crypto::randomFill(otherTrustchainId);
    CHECK_NOTHROW(ensureIdentitiesInTrustchain({}, otherTrustchainId));
  }

  SECTION("does not throw with valid public identities")
  {
    Trustchain::TrustchainId otherTrustchainId;
    Crypto::randomFill(otherTrustchainId);
    auto kp = Crypto::makeSignatureKeyPair();

    auto identity =
        createTestPermanentIdentity(otherTrustchainId, kp.privateKey);
    CHECK_NOTHROW(ensureIdentitiesInTrustchain({identity}, otherTrustchainId));
  }

  SECTION("does not throw with valid public provisional identities")
  {
    Trustchain::TrustchainId otherTrustchainId;
    Crypto::randomFill(otherTrustchainId);

    auto identity = createTestProvisionalIdentity(otherTrustchainId);
    CHECK_NOTHROW(ensureIdentitiesInTrustchain({identity}, otherTrustchainId));
  }

  SECTION("throws with invalid identities")
  {
    Trustchain::TrustchainId otherTrustchainId;
    Crypto::randomFill(otherTrustchainId);

    auto identity =
        createTestPermanentIdentity(trustchainId, trustchainPrivateKey);
    TANKER_CHECK_THROWS_WITH_CODE(
        ensureIdentitiesInTrustchain({identity}, otherTrustchainId),
        Errors::Errc::InvalidArgument);
  }

  SECTION("throws with invalid provisional identities")
  {
    Trustchain::TrustchainId otherTrustchainId;
    Crypto::randomFill(otherTrustchainId);

    auto identity = createTestProvisionalIdentity(trustchainId);
    TANKER_CHECK_THROWS_WITH_CODE(
        ensureIdentitiesInTrustchain({identity}, otherTrustchainId),
        Errors::Errc::InvalidArgument);
  }

  SECTION("throws with a mix of valid and invalid identities")
  {
    Trustchain::TrustchainId otherTrustchainId;
    Crypto::randomFill(otherTrustchainId);
    auto kp = Crypto::makeSignatureKeyPair();

    auto validIdentity =
        createTestPermanentIdentity(otherTrustchainId, kp.privateKey);
    auto validProvisionalIdentity =
        createTestProvisionalIdentity(otherTrustchainId);
    auto invalidIdentity =
        createTestPermanentIdentity(trustchainId, trustchainPrivateKey);
    auto invalidProvisionalIdentity =
        createTestProvisionalIdentity(trustchainId);

    TANKER_CHECK_THROWS_WITH_CODE(
        ensureIdentitiesInTrustchain({validIdentity,
                                      invalidIdentity,
                                      validProvisionalIdentity,
                                      invalidProvisionalIdentity},
                                     otherTrustchainId),
        Errors::Errc::InvalidArgument);
  }
}
