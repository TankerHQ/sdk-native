#include <Tanker/Verification/Request.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/Encryptor/v2.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Types/EncryptedEmail.hpp>
#include <Tanker/Types/Overloaded.hpp>

#include <mgs/base64.hpp>
#include <nlohmann/json.hpp>

#include <range/v3/range/conversion.hpp>
#include <range/v3/view/transform.hpp>

#include <boost/variant2/variant.hpp>

TLOG_CATEGORY(Tanker::Verification);

namespace
{

using namespace Tanker::Errors;

void checkNotEmpty(std::string const& value, std::string const& description)
{
  if (value.empty())
  {
    throw formatEx(Errc::InvalidArgument, "{:s} should not be empty", description);
  }
}

template <typename Ret = Tanker::Crypto::Hash, typename T>
Ret hashField(T const& field)
{
  return Tanker::Crypto::generichash<Ret>(gsl::make_span(field).template as_span<std::uint8_t const>());
}

// This function is NOT exposed to our users. It is important that others
// prehash passwords differently than we do, otherwise when the password is the
// same, both parties would know the value that the other accepts as password
// hash. The 'nothing up my sleeve' pepper constant provides confidence it
// wasn't picked to match a value that might be already in use elsewhere
// (whether accidentally or maliciously).
Tanker::Trustchain::HashedE2ePassphrase prehashE2eVerificationPassphrase(Tanker::E2ePassphrase const& passphrase)
{
  static constexpr char pepper[] = "tanker e2e verification passphrase pepper";
  std::vector<std::uint8_t> buffer(passphrase.begin(), passphrase.end());
  buffer.insert(buffer.end(), pepper, pepper + sizeof(pepper) - 1);
  return Tanker::Crypto::generichash<Tanker::Trustchain::HashedE2ePassphrase>(
      gsl::make_span(buffer).template as_span<std::uint8_t const>());
}
}

namespace Tanker::Verification
{
RequestWithVerif makeRequestWithVerif(RequestVerification const& verification,
                                      Crypto::SymmetricKey const& userSecret,
                                      std::optional<Crypto::SignatureKeyPair> const& secretProvisionalSigKey,
                                      std::optional<std::string> const& withTokenNonce)
{
  auto verif = boost::variant2::visit(
      overloaded{
          [&](ByEmail const& v) -> RequestVerificationPayload {
            checkNotEmpty(v.verificationCode.string(), "verification code");
            checkNotEmpty(v.email.string(), "email");

            EncryptedEmail encryptedEmail(EncryptorV2::encryptedSize(v.email.size()));
            EncryptorV2::encryptSync(encryptedEmail, gsl::make_span(v.email).as_span<uint8_t const>(), userSecret);

            return EncryptedEmailVerification{hashField(v.email), std::move(encryptedEmail), v.verificationCode};
          },
          [&](ByPhoneNumber const& v) -> RequestVerificationPayload {
            checkNotEmpty(v.verificationCode.string(), "verification code");
            checkNotEmpty(v.phoneNumber.string(), "phoneNumber");

            EncryptedPhoneNumber encryptedPhoneNumber(EncryptorV2::encryptedSize(v.phoneNumber.size()));
            EncryptorV2::encryptSync(
                encryptedPhoneNumber, gsl::make_span(v.phoneNumber).as_span<std::uint8_t const>(), userSecret);

            auto const provisionalSalt = secretProvisionalSigKey.has_value() ?
                                             std::make_optional(hashField(secretProvisionalSigKey->privateKey)) :
                                             std::nullopt;

            return EncryptedPhoneNumberVerification{v.phoneNumber,
                                                    hashField(userSecret),
                                                    provisionalSalt,
                                                    std::move(encryptedPhoneNumber),
                                                    v.verificationCode};
          },
          [](Passphrase const& p) -> RequestVerificationPayload {
            checkNotEmpty(p.string(), "passphrase");
            return Trustchain::HashedPassphrase{hashField(p)};
          },
          [](E2ePassphrase const& p) -> RequestVerificationPayload {
            checkNotEmpty(p.string(), "e2ePassphrase");
            return Trustchain::HashedE2ePassphrase{prehashE2eVerificationPassphrase(p)};
          },
          [](VerificationKey const& v) -> RequestVerificationPayload {
            checkNotEmpty(v.string(), "verificationKey");
            return v;
          },
          [](OidcIdTokenWithChallenge const& v) -> RequestVerificationPayload {
            // sanity checks are performed before fetching the challenge
            TWARNING(
                "'testNonce' field should be used for tests purposes only. It "
                "will be rejected for non-test Tanker application");
            return v;
          },
          [&](PreverifiedEmail const& v) -> RequestVerificationPayload {
            checkNotEmpty(v.string(), "email");
            EncryptedEmail encryptedEmail(EncryptorV2::encryptedSize(v.size()));
            EncryptorV2::encryptSync(encryptedEmail, gsl::make_span(v).as_span<uint8_t const>(), userSecret);

            return EncryptedPreverifiedEmailVerification{hashField(v), std::move(encryptedEmail)};
          },
          [&](PreverifiedPhoneNumber const& v) -> RequestVerificationPayload {
            checkNotEmpty(v.string(), "phoneNumber");
            EncryptedPhoneNumber encryptedPhoneNumber(EncryptorV2::encryptedSize(v.size()));
            EncryptorV2::encryptSync(encryptedPhoneNumber, gsl::make_span(v).as_span<std::uint8_t const>(), userSecret);

            auto const provisionalSalt = secretProvisionalSigKey.has_value() ?
                                             std::make_optional(hashField(secretProvisionalSigKey->privateKey)) :
                                             std::nullopt;

            return EncryptedPreverifiedPhoneNumberVerification{
                PhoneNumber{v.string()}, hashField(userSecret), provisionalSalt, std::move(encryptedPhoneNumber)};
          },
      },
      verification);
  return {verif, withTokenNonce};
}

RequestWithVerif makeRequestWithVerif(Verification const& verification,
                                      Crypto::SymmetricKey const& userSecret,
                                      std::optional<Crypto::SignatureKeyPair> const& secretProvisionalSigKey,
                                      std::optional<std::string> const& withTokenNonce)
{
  namespace bv2 = boost::variant2;
  if (auto const v = bv2::get_if<OidcIdToken>(&verification))
  {
    checkNotEmpty(v->token, "oidcIdToken");
    return {*v, withTokenNonce};
  }

  auto verif =
      bv2::visit(overloaded{[&](auto const& v) -> RequestVerification { return v; },
                            [&](OidcIdToken const& v) -> RequestVerification { throw bv2::bad_variant_access{}; }},
                 verification);

  return makeRequestWithVerif(verif, userSecret, secretProvisionalSigKey, withTokenNonce);
}

std::vector<RequestWithVerif> makeRequestWithVerifs(std::vector<Verification> const& verifications,
                                                    Crypto::SymmetricKey const& userSecret)
{
  return verifications | ranges::views::transform([&userSecret](auto const& verification) {
           return makeRequestWithVerif(verification, userSecret, std::nullopt, std::nullopt);
         }) |
         ranges::to<std::vector>;
}

void to_json(nlohmann::json& j, RequestWithVerif const& request)
{
  j = nlohmann::json(request.verification);
  if (request.withTokenNonce.has_value())
    j["with_token"] = {{"nonce", *request.withTokenNonce}};
}

RequestWithSession makeRequestWithSession(Identity::SecretProvisionalIdentity const& identity,
                                          Crypto::SymmetricKey const& userSecret)
{
  SessionRequestValue value;
  if (identity.target == Identity::TargetType::Email)
  {
    value = EmailSessionRequest{Email(identity.value)};
  }
  else if (identity.target == Identity::TargetType::PhoneNumber)
  {
    const auto provisionalSalt = hashField(identity.appSignatureKeyPair.privateKey);
    value = PhoneNumberSessionRequest{PhoneNumber(identity.value), hashField(userSecret), provisionalSalt};
  }
  else
  {
    throw Errors::AssertionError(
        "makeRequestWithSession: Unexpected target for secret provisional "
        "identity");
  }

  return {identity.target, value};
}

void to_json(nlohmann::json& j, RequestWithSession const& request)
{
  j = nlohmann::json(request.value);
  j["target"] = to_string(request.target);
}

void to_json(nlohmann::json& j, SetVerifMethodRequest const& request)
{
  j["verification"] = request.verification;
  if (request.encVkForUserSecret.has_value())
    j["encrypted_verification_key_for_user_secret"] = *request.encVkForUserSecret;
  if (request.encVkForUserKey.has_value())
    j["encrypted_verification_key_for_user_key"] = *request.encVkForUserKey;
  if (request.encVkForE2ePass.has_value())
    j["encrypted_verification_key_for_e2e_passphrase"] = *request.encVkForE2ePass;
}
}

namespace nlohmann
{
template <>
void adl_serializer<Tanker::Verification::RequestVerificationPayload>::to_json(
    json& j, Tanker::Verification::RequestVerificationPayload const& request)
{
  using namespace Tanker;
  boost::variant2::visit(overloaded{
                             [&](Verification::EncryptedEmailVerification const& e) {
                               j["hashed_email"] = e.hashedEmail;
                               j["verification_code"] = e.verificationCode;
                               j["v2_encrypted_email"] = e.encryptedEmail;
                             },
                             [&](Verification::EncryptedPhoneNumberVerification const& e) {
                               j["phone_number"] = e.phoneNumber;
                               j["verification_code"] = e.verificationCode;
                               j["encrypted_phone_number"] = e.encryptedPhoneNumber;
                               j["user_salt"] = e.userSalt;
                               if (e.provisionalSalt)
                               {
                                 j["provisional_salt"] = *e.provisionalSalt;
                               }
                             },
                             [&](Trustchain::HashedPassphrase const& p) { j["hashed_passphrase"] = p; },
                             [&](Trustchain::HashedE2ePassphrase const& p) { j["hashed_e2e_passphrase"] = p; },
                             [&](OidcIdToken const& t) { j["oidc_id_token"] = t.token; },
                             [&](Verification::OidcIdTokenWithChallenge const& t) {
                               j["oidc_id_token"] = t.oidcIdToken.token;
                               j["oidc_challenge"] = t.oidcChallenge.challenge;
                               j["oidc_challenge_signature"] = t.oidcChallenge.signature;
                               if (t.oidcTestNonce)
                               {
                                 j["oidc_test_nonce"] = *t.oidcTestNonce;
                               }
                             },
                             [](VerificationKey const& v) {},
                             [&](Verification::EncryptedPreverifiedEmailVerification const& e) {
                               j["hashed_email"] = e.hashedEmail;
                               j["v2_encrypted_email"] = e.encryptedEmail;
                               j["is_preverified"] = true;
                             },
                             [&](Verification::EncryptedPreverifiedPhoneNumberVerification const& e) {
                               j["phone_number"] = e.phoneNumber;
                               j["encrypted_phone_number"] = e.encryptedPhoneNumber;
                               j["user_salt"] = e.userSalt;
                               j["is_preverified"] = true;
                               if (e.provisionalSalt)
                               {
                                 j["provisional_salt"] = *e.provisionalSalt;
                               }
                             },
                         },
                         request);
}

template <>
void adl_serializer<Tanker::Verification::SessionRequestValue>::to_json(
    json& j, Tanker::Verification::SessionRequestValue const& request)
{
  using namespace Tanker;
  boost::variant2::visit(overloaded{
                             [&](Verification::EmailSessionRequest const& e) { j["email"] = e.email; },
                             [&](Verification::PhoneNumberSessionRequest const& e) {
                               j["phone_number"] = e.phoneNumber;
                               j["provisional_salt"] = e.provisionalSalt;
                               j["user_secret_salt"] = e.userSalt;
                             },
                         },
                         request);
}
}
