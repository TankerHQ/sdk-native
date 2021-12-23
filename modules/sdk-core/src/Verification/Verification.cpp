#include <Tanker/Verification/Verification.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/Encryptor/v2.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>
#include <Tanker/Types/Overloaded.hpp>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <mgs/base64.hpp>
#include <mgs/base64url.hpp>
#include <nlohmann/json.hpp>

namespace Tanker::Verification
{
namespace
{
template <typename Ret, typename T>
tc::cotask<Ret> decryptMethod(T const& encrypted,
                              Crypto::SymmetricKey const& userSecret)
{
  Ret decrypted(EncryptorV2::decryptedSize(encrypted), 0);

  TC_AWAIT(
      EncryptorV2::decrypt(reinterpret_cast<std::uint8_t*>(decrypted.data()),
                           userSecret,
                           encrypted));
  TC_RETURN(decrypted);
}
}

VerificationMethod VerificationMethod::from(Verification const& v)
{
  return boost::variant2::visit(
      overloaded{
          [](Passphrase const&) -> VerificationMethod { return Passphrase{}; },
          [](VerificationKey const&) -> VerificationMethod {
            return VerificationKey{};
          },
          [](OidcIdToken const&) -> VerificationMethod {
            return OidcIdToken{};
          },
          [](ByEmail const& v) -> VerificationMethod { return v.email; },
          [](ByPhoneNumber const& v) -> VerificationMethod {
            return v.phoneNumber;
          },
          [](PreverifiedEmail const& v) -> VerificationMethod { return v; },
          [](PreverifiedPhoneNumber const& v) -> VerificationMethod {
            return v;
          }},
      v);
}

tc::cotask<std::vector<VerificationMethod>> decryptMethods(
    std::vector<boost::variant2::variant<VerificationMethod,
                                         EncryptedVerificationMethod>>&
        encryptedMethods,
    Crypto::SymmetricKey const& userSecret)
{
  std::vector<VerificationMethod> methods;
  methods.reserve(encryptedMethods.size());

  auto const decryptLambda =
      [&](EncryptedVerificationMethod const& encryptedMethod)
      -> tc::cotask<void> {
    TC_AWAIT(encryptedMethod.visit(overloaded{
        [&](EncryptedEmail const& encryptedEmail) -> tc::cotask<void> {
          methods.push_back(
              TC_AWAIT(decryptMethod<Email>(encryptedEmail, userSecret)));
        },
        [&](EncryptedPhoneNumber const& encryptedPhoneNumber)
            -> tc::cotask<void> {
          methods.push_back(TC_AWAIT(
              decryptMethod<PhoneNumber>(encryptedPhoneNumber, userSecret)));
        },
        [&](EncryptedPreverifiedEmail const& encryptedEmail)
            -> tc::cotask<void> {
          methods.push_back(TC_AWAIT(
              decryptMethod<PreverifiedEmail>(encryptedEmail, userSecret)));
        },
        [&](EncryptedPreverifiedPhoneNumber const& encryptedPhoneNumber)
            -> tc::cotask<void> {
          methods.push_back(TC_AWAIT(decryptMethod<PreverifiedPhoneNumber>(
              encryptedPhoneNumber, userSecret)));
        },

    }));
  };

  for (auto& method : encryptedMethods)
  {
    TC_AWAIT(boost::variant2::visit(
        overloaded{decryptLambda,
                   [&](VerificationMethod const& method) -> tc::cotask<void> {
                     methods.push_back(method);
                     TC_RETURN();
                   }},
        method));
  }

  TC_RETURN(methods);
}

void from_json(nlohmann::json const& j,
               boost::variant2::variant<VerificationMethod,
                                        EncryptedVerificationMethod>& m)
{
  auto const value = j.at("type").get<std::string>();
  auto const isPreverified = j.at("is_preverified").get<bool>();
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
    if (isPreverified)
    {
      m = EncryptedPreverifiedEmail{decodedEmail.begin(), decodedEmail.end()};
    }
    else
    {
      m = EncryptedEmail{decodedEmail.begin(), decodedEmail.end()};
    }
  }
  else if (value == "phone_number")
  {
    auto const phoneNumber = j.at("encrypted_phone_number").get<std::string>();
    auto const decodedPhoneNumber = mgs::base64::decode(phoneNumber);
    if (isPreverified)
    {
      m = EncryptedPreverifiedPhoneNumber{decodedPhoneNumber.begin(),
                                          decodedPhoneNumber.end()};
    }
    else
    {
      m = EncryptedPhoneNumber{decodedPhoneNumber.begin(),
                               decodedPhoneNumber.end()};
    }
  }
  else
    throw formatEx(Errors::Errc::UpgradeRequired,
                   "unsupported verification method");
}

void validateVerification(
    Verification const& verification,
    Identity::SecretProvisionalIdentity const& provisionalIdentity)
{
  namespace bv = boost::variant2;
  namespace ba = boost::algorithm;

  if (!(bv::holds_alternative<ByEmail>(verification) ||
        bv::holds_alternative<ByPhoneNumber>(verification) ||
        bv::holds_alternative<OidcIdToken>(verification)))
    throw Errors::Exception(
        make_error_code(Errors::Errc::InvalidArgument),
        "unknown verification method for provisional identity");

  if (auto const emailVerification = bv::get_if<ByEmail>(&verification))
  {
    if (emailVerification->email != Email{provisionalIdentity.value})
      throw Errors::Exception(
          make_error_code(Errors::Errc::InvalidArgument),
          "verification email does not match provisional identity");
  }
  if (auto const phoneNumberVerification =
          bv::get_if<ByPhoneNumber>(&verification))
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
