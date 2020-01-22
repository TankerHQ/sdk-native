#include <Tanker/Unlock/Verification.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/Errors/AssertionError.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Unlock
{

VerificationMethod VerificationMethod::from(Verification const& v)
{
  using boost::variant2::holds_alternative;
  VerificationMethod m;
  if (holds_alternative<Passphrase>(v))
    m = Passphrase{};
  else if (holds_alternative<VerificationKey>(v))
    m = VerificationKey{};
  else if (holds_alternative<OidcIdToken>(v))
    m = OidcIdToken{};
  else if (auto const email = boost::variant2::get_if<EmailVerification>(&v))
    m = email->email;
  else
    throw Errors::AssertionError("use of an outdated sdk");
  return m;
}

void decryptEmailMethods(std::vector<VerificationMethod>& encryptedMethods,
                         Crypto::SymmetricKey const& userSecret)
{
  for (auto& method : encryptedMethods)
  {
    if (auto encryptedEmail = method.get_if<Unlock::EncryptedEmail>())
    {
      auto const decryptedEmail = Crypto::decryptAead(
          userSecret,
          gsl::make_span(*encryptedEmail).as_span<std::uint8_t const>());
      method = Email{decryptedEmail.begin(), decryptedEmail.end()};
    }
  }
}

void from_json(nlohmann::json const& j, VerificationMethod& m)
{
  auto const value = j.at("type").get<std::string>();
  if (value == "passphrase")
    m = Passphrase{};
  else if (value == "verificationKey")
    m = VerificationKey{};
  else if (value == "oidc_id_token")
    m = OidcIdToken{};
  else if (value == "email")
  {
    auto const email = j.at("encrypted_email").get<std::string>();
    auto const decodedEmail = cppcodec::base64_rfc4648::decode(email);
    m = EncryptedEmail{decodedEmail.begin(), decodedEmail.end()};
  }
  else
    throw Errors::AssertionError("use of an outdated sdk");
}
}
}
