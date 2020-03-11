#include <Tanker/Unlock/Request.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/Encryptor/v2.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
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

template <typename T>
Tanker::Crypto::Hash hashField(T const& field)
{
  return Tanker::Crypto::generichash(
      gsl::make_span(field).template as_span<std::uint8_t const>());
}
}

namespace Tanker::Unlock
{
Request makeRequest(Unlock::Verification const& verification,
                    Crypto::SymmetricKey const& userSecret)
{
  return boost::variant2::visit(
      overloaded{
          [&](Unlock::EmailVerification const& v) -> Request {
            checkNotEmpty(v.verificationCode.string(), "verification code");
            checkNotEmpty(v.email.string(), "email");

            std::vector<uint8_t> encryptedEmail(
                EncryptorV2::encryptedSize(v.email.size()));
            EncryptorV2::encryptSync(
                encryptedEmail.data(),
                gsl::make_span(v.email).as_span<uint8_t const>(),
                userSecret);

            return EncryptedEmailVerification{
                hashField(v.email), encryptedEmail, v.verificationCode};
          },
          [](Passphrase const& p) -> Request {
            checkNotEmpty(p.string(), "passphrase");
            return Trustchain::HashedPassphrase{hashField(p)};
          },
          [](VerificationKey const& v) -> Request {
            checkNotEmpty(v.string(), "verificationKey");
            return v;
          },
          [](OidcIdToken const& v) -> Request {
            checkNotEmpty(v.string(), "oidcIdToken");
            return v;
          },
      },
      verification);
}
}

namespace nlohmann
{
template <>
void adl_serializer<Tanker::Unlock::Request>::to_json(
    json& j, Tanker::Unlock::Request const& request)
{
  using namespace Tanker;
  boost::variant2::visit(
      overloaded{
          [&](Unlock::EncryptedEmailVerification const& e) {
            std::vector<std::uint8_t> encrypted_email;
            std::tie(
                j["hashed_email"], encrypted_email, j["verification_code"]) = e;
            j["v2_encrypted_email"] = mgs::base64::encode(encrypted_email);
          },
          [&](Trustchain::HashedPassphrase const& p) {
            j["hashed_passphrase"] = p;
          },
          [&](OidcIdToken const& t) { j["oidc_id_token"] = t.string(); },
          [](VerificationKey const& v) {},
      },
      request);
}
}
