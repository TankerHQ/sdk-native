#include <Tanker/Unlock/Verification.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <cppcodec/base64_rfc4648.hpp>
#include <cppcodec/base64_url_unpadded.hpp>
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

tc::cotask<void> decryptEmailMethods(
    std::vector<VerificationMethod>& encryptedMethods,
    Crypto::SymmetricKey const& userSecret)
{
  for (auto& method : encryptedMethods)
  {
    if (auto encryptedEmail = method.get_if<Unlock::EncryptedEmail>())
    {
      auto const decryptedEmail = TC_AWAIT(Encryptor::decryptFallbackAead(
          userSecret,
          gsl::make_span(*encryptedEmail).as_span<std::uint8_t const>()));
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
void validateVerification(
    Unlock::Verification const& verification,
    Identity::SecretProvisionalIdentity const& provisionalIdentity)
{
  namespace bv = boost::variant2;
  namespace ba = boost::algorithm;

  if (!(bv::holds_alternative<Unlock::EmailVerification>(verification) ||
        bv::holds_alternative<OidcIdToken>(verification)))
    throw Errors::Exception(
        make_error_code(Errors::Errc::InvalidArgument),
        "unknown verification method for provisional identity");

  if (auto const emailVerification =
          bv::get_if<Unlock::EmailVerification>(&verification))
  {
    if (emailVerification->email != Email{provisionalIdentity.value})
      throw Errors::Exception(
          make_error_code(Errors::Errc::InvalidArgument),
          "verification email does not match provisional identity");
  }
  else if (auto const oidcIdToken = bv::get_if<OidcIdToken>(&verification))
  {
    std::string jwtEmail;
    try
    {
      std::vector<std::string> res;
      ba::split(res, *oidcIdToken, ba::is_any_of("."));
      jwtEmail = nlohmann::json::parse(
                     cppcodec::base64_url_unpadded::decode(res.at(1)))
                     .at("email");
    }
    catch (...)
    {
      throw Errors::Exception(make_error_code(Errors::Errc::InvalidArgument),
                              "Failed to parse verification oidcIdToken");
    }
    if (jwtEmail != provisionalIdentity.value)
      throw Errors::Exception(
          make_error_code(Errors::Errc::InvalidArgument),
          "verification does not match provisional identity");
  }
}
}
}
