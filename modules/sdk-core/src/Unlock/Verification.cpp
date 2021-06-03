#include <Tanker/Unlock/Verification.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/Encryptor/v2.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <mgs/base64.hpp>
#include <mgs/base64url.hpp>
#include <nlohmann/json.hpp>

namespace Tanker::Unlock
{
namespace
{
template <typename Ret, typename T>
Ret decryptMethod(T const& encrypted, Crypto::SymmetricKey const& userSecret)
{
  Ret decrypted(EncryptorV2::decryptedSize(encrypted), 0);

  EncryptorV2::decrypt(
      reinterpret_cast<std::uint8_t*>(decrypted.data()), userSecret, encrypted);
  return decrypted;
}
}

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
  else if (auto const phoneNumber =
               boost::variant2::get_if<PhoneNumberVerification>(&v))
    m = phoneNumber->phoneNumber;
  else
    throw Errors::AssertionError("use of an outdated sdk");
  return m;
}

tc::cotask<void> decryptMethods(
    std::vector<VerificationMethod>& encryptedMethods,
    Crypto::SymmetricKey const& userSecret)
{
  for (auto& method : encryptedMethods)
  {
    if (auto encryptedEmail = method.get_if<EncryptedEmail>())
      method = decryptMethod<Email>(*encryptedEmail, userSecret);
    else if (auto encryptedPhoneNumber = method.get_if<EncryptedPhoneNumber>())
      method = decryptMethod<PhoneNumber>(*encryptedPhoneNumber, userSecret);
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
    auto const decodedEmail = mgs::base64::decode(email);
    m = EncryptedEmail{decodedEmail.begin(), decodedEmail.end()};
  }
  else if (value == "phone_number")
  {
    auto const phoneNumber = j.at("encrypted_phone_number").get<std::string>();
    auto const decodedPhoneNumber = mgs::base64::decode(phoneNumber);
    m = EncryptedPhoneNumber{decodedPhoneNumber.begin(),
                             decodedPhoneNumber.end()};
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
  if (auto const phoneNumberVerification =
          bv::get_if<Unlock::PhoneNumberVerification>(&verification))
  {
    if (phoneNumberVerification->phoneNumber !=
        PhoneNumber{provisionalIdentity.value})
      throw Errors::Exception(
          make_error_code(Errors::Errc::InvalidArgument),
          "verification phone number does not match provisional identity");
  }
  else if (auto const oidcIdToken = bv::get_if<OidcIdToken>(&verification))
  {
    std::string jwtEmail;
    try
    {
      std::vector<std::string> res;
      ba::split(res, *oidcIdToken, ba::is_any_of("."));
      nlohmann::json::parse(mgs::base64url_nopad::decode(res.at(1)))
          .at("email")
          .get_to(jwtEmail);
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
