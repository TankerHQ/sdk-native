#include <Tanker/Verification/Request.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/Encryptor/v2.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>
#include <Tanker/Types/EncryptedEmail.hpp>
#include <Tanker/Types/Overloaded.hpp>

#include <mgs/base64.hpp>
#include <nlohmann/json.hpp>

#include <boost/variant2/variant.hpp>

namespace
{

using namespace Tanker::Errors;

void checkNotEmpty(std::string const& value, std::string const& description)
{
  if (value.empty())
  {
    throw formatEx(
        Errc::InvalidArgument, "{:s} should not be empty", description);
  }
}

template <typename Ret = Tanker::Crypto::Hash, typename T>
Ret hashField(T const& field)
{
  return Tanker::Crypto::generichash<Ret>(
      gsl::make_span(field).template as_span<std::uint8_t const>());
}
}

namespace Tanker::Verification
{
RequestWithVerif makeRequestWithVerif(
    Verification const& verification,
    Crypto::SymmetricKey const& userSecret,
    std::optional<Crypto::SignatureKeyPair> const& secretProvisionalSigKey,
    std::optional<std::string> const& withTokenNonce)
{
  auto verif = boost::variant2::visit(
      overloaded{
          [&](ByEmail const& v) -> RequestVerificationMethods {
            checkNotEmpty(v.verificationCode.string(), "verification code");
            checkNotEmpty(v.email.string(), "email");

            EncryptedEmail encryptedEmail(
                EncryptorV2::encryptedSize(v.email.size()));
            EncryptorV2::encryptSync(
                encryptedEmail.data(),
                gsl::make_span(v.email).as_span<uint8_t const>(),
                userSecret);

            return EncryptedEmailVerification{hashField(v.email),
                                              std::move(encryptedEmail),
                                              v.verificationCode};
          },
          [&](PhoneNumberVerification const& v) -> RequestVerificationMethods {
            checkNotEmpty(v.verificationCode.string(), "verification code");
            checkNotEmpty(v.phoneNumber.string(), "phoneNumber");

            EncryptedPhoneNumber encryptedPhoneNumber(
                EncryptorV2::encryptedSize(v.phoneNumber.size()));
            EncryptorV2::encryptSync(
                encryptedPhoneNumber.data(),
                gsl::make_span(v.phoneNumber).as_span<std::uint8_t const>(),
                userSecret);

            auto const provisionalSalt =
                secretProvisionalSigKey.has_value() ?
                    std::make_optional(
                        hashField(secretProvisionalSigKey->privateKey)) :
                    std::nullopt;

            return EncryptedPhoneNumberVerification{
                v.phoneNumber,
                hashField(userSecret),
                provisionalSalt,
                std::move(encryptedPhoneNumber),
                v.verificationCode};
          },
          [](Passphrase const& p) -> RequestVerificationMethods {
            checkNotEmpty(p.string(), "passphrase");
            return Trustchain::HashedPassphrase{hashField(p)};
          },
          [](VerificationKey const& v) -> RequestVerificationMethods {
            checkNotEmpty(v.string(), "verificationKey");
            return v;
          },
          [](OidcIdToken const& v) -> RequestVerificationMethods {
            checkNotEmpty(v.string(), "oidcIdToken");
            return v;
          },
      },
      verification);
  return {verif, withTokenNonce};
}

void to_json(nlohmann::json& j, RequestWithVerif const& request)
{
  j = nlohmann::json(request.verification);
  if (request.withTokenNonce.has_value())
    j["with_token"] = {{"nonce", *request.withTokenNonce}};
}

RequestWithSession makeRequestWithSession(
    Identity::SecretProvisionalIdentity const& identity,
    Crypto::SymmetricKey const& userSecret)
{
  SessionRequestValue value;
  if (identity.target == Identity::TargetType::Email)
  {
    value = EmailSessionRequest{Email(identity.value)};
  }
  else if (identity.target == Identity::TargetType::PhoneNumber)
  {
    const auto provisionalSalt =
        hashField(identity.appSignatureKeyPair.privateKey);
    value = PhoneNumberSessionRequest{
        PhoneNumber(identity.value), hashField(userSecret), provisionalSalt};
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
}

namespace nlohmann
{
template <>
void adl_serializer<Tanker::Verification::RequestVerificationMethods>::to_json(
    json& j, Tanker::Verification::RequestVerificationMethods const& request)
{
  using namespace Tanker;
  boost::variant2::visit(
      overloaded{
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
          [&](Trustchain::HashedPassphrase const& p) {
            j["hashed_passphrase"] = p;
          },
          [&](OidcIdToken const& t) { j["oidc_id_token"] = t.string(); },
          [](VerificationKey const& v) {},
      },
      request);
}

template <>
void adl_serializer<Tanker::Verification::SessionRequestValue>::to_json(
    json& j, Tanker::Verification::SessionRequestValue const& request)
{
  using namespace Tanker;
  boost::variant2::visit(
      overloaded{
          [&](Verification::EmailSessionRequest const& e) {
            j["email"] = e.email;
          },
          [&](Verification::PhoneNumberSessionRequest const& e) {
            j["phone_number"] = e.phoneNumber;
            j["provisional_salt"] = e.provisionalSalt;
            j["user_secret_salt"] = e.userSalt;
          },
      },
      request);
}
}
