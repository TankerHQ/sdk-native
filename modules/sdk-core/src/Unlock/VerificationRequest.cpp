#include <Tanker/Unlock/VerificationRequest.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Errors/AssertionError.hpp>

#include <nlohmann/json.hpp>
#include <optional.hpp>

namespace Tanker
{
namespace Unlock
{
nonstd::optional<VerificationRequest> makeVerificationRequest(
    Verification const& verification, Crypto::SymmetricKey const& userSecret)
{
  if (auto const verif = mpark::get_if<EmailVerification>(&verification))
    return EncryptedEmailVerification{
        verif->email,
        Crypto::encryptAead(
            userSecret, gsl::make_span(verif->email).as_span<uint8_t const>()),
        verif->verificationCode};
  else if (auto const pass = mpark::get_if<Password>(&verification))
    return Crypto::generichash(gsl::make_span(*pass).as_span<uint8_t const>());
  else if (mpark::holds_alternative<VerificationKey>(verification))
    return nonstd::nullopt;
  throw Errors::AssertionError("unsupported verification request");
}

void to_json(nlohmann::json& j, VerificationRequest const& vReq)
{
  if (auto const eev = mpark::get_if<EncryptedEmailVerification>(&vReq))
  {
    j["email"] = Crypto::generichash(
        gsl::make_span(eev->email).as_span<std::uint8_t const>());
    j["encrypted_email"] =
        cppcodec::base64_rfc4648::encode(eev->encrytpedEmail);
    j["verification_code"] = eev->verificationCode;
  }
  else if (auto const hpass = mpark::get_if<Crypto::Hash>(&vReq))
    j["passphrase"] = cppcodec::base64_rfc4648::encode(*hpass);
}
}
}
