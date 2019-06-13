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
void to_json(nlohmann::json& j, VerificationMethod const& method)
{
  if (method.holds_alternative<Password>())
    j.push_back({{"type", "password"}});
  else if (method.holds_alternative<VerificationKey>())
    j.push_back({{"type", "verificationKey"}});
  else if (auto const email = method.get_if<Email>())
    j.push_back({{"type", "email"},
                 {"email", cppcodec::base64_rfc4648::encode(*email)}});
  else
    throw Errors::AssertionError("use of an outdated sdk");
}

void from_json(nlohmann::json const& j, VerificationMethod& m)
{
  auto const value = j.at("type").get<std::string>();
  if (value == "password")
    m = Password{};
  else if (value == "verificationKey")
    m = VerificationKey{};
  else if (value == "email")
  {
    auto const email = j.at("email").get<std::string>();
    auto const decodedEmail = cppcodec::base64_rfc4648::decode(email);
    m = Email{decodedEmail.begin(), decodedEmail.end()};
  }
  else
    throw Errors::AssertionError("use of an outdated sdk");
}

nlohmann::json makeVerificationRequest(Verification const& verification,
                                       Crypto::SymmetricKey const& userSecret)
{
  nlohmann::json request;
  if (auto const verif = mpark::get_if<EmailVerification>(&verification))
  {
    request["email"] = Crypto::generichash(
        gsl::make_span(verif->email).as_span<std::uint8_t const>());
    request["encrypted_email"] =
        cppcodec::base64_rfc4648::encode(Crypto::encryptAead(
            userSecret, gsl::make_span(verif->email).as_span<uint8_t const>()));
    request["verification_code"] = verif->verificationCode;
  }
  else if (auto const pass = mpark::get_if<Password>(&verification))
  {
    request["passphrase"] = cppcodec::base64_rfc4648::encode(
        Crypto::generichash(gsl::make_span(*pass).as_span<uint8_t const>()));
  }
  else if (!mpark::holds_alternative<VerificationKey>(verification))
    // as we return an empty json for verification key the only thing to do if
    // it is NOT a verificationKey is to throw
    throw Errors::AssertionError("unsupported verification request");
  return request;
}
}
}
