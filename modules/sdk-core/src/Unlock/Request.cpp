#include <Tanker/Unlock/Request.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/Types/Overloaded.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>

#include <boost/variant2/variant.hpp>

namespace
{
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
            return EncryptedEmailVerification{
                hashField(v.email),
                Crypto::encryptAead(
                    userSecret,
                    gsl::make_span(v.email).as_span<uint8_t const>()),
                v.verificationCode};
          },
          [](Passphrase const& p) -> Request {
            return Trustchain::HashedPassphrase{hashField(p)};
          },
          [](VerificationKey const& v) -> Request { return v; },
          [](OidcIdToken const& v) -> Request { return v; },
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
            j["encrypted_email"] =
                cppcodec::base64_rfc4648::encode(encrypted_email);
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