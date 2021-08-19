#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/VariantImplementation.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/EncryptedEmail.hpp>
#include <Tanker/Types/EncryptedPhoneNumber.hpp>
#include <Tanker/Types/OidcIdToken.hpp>
#include <Tanker/Types/Passphrase.hpp>
#include <Tanker/Types/PhoneNumber.hpp>
#include <Tanker/Types/VerificationCode.hpp>
#include <Tanker/Types/VerificationKey.hpp>

#include <boost/variant2/variant.hpp>
#include <nlohmann/json_fwd.hpp>
#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace Identity
{
struct SecretProvisionalIdentity;
}

namespace Verification
{
struct EmailVerification
{
  Email email;
  VerificationCode verificationCode;
};

struct PhoneNumberVerification
{
  PhoneNumber phoneNumber;
  VerificationCode verificationCode;
};

using Verification = boost::variant2::variant<VerificationKey,
                                              EmailVerification,
                                              Passphrase,
                                              OidcIdToken,
                                              PhoneNumberVerification>;

class VerificationMethod
{
  TANKER_TRUSTCHAIN_ACTION_VARIANT_IMPLEMENTATION_ZERO(VerificationMethod,
                                                       (VerificationKey,
                                                        EncryptedEmail,
                                                        Email,
                                                        Passphrase,
                                                        OidcIdToken,
                                                        EncryptedPhoneNumber,
                                                        PhoneNumber))

  static VerificationMethod from(Verification const& v);

private:
  friend void from_json(nlohmann::json const&, VerificationMethod&);
  friend bool operator<(VerificationMethod const& a,
                        VerificationMethod const& b);
};

tc::cotask<void> decryptMethods(
    std::vector<VerificationMethod>& encryptedMethods,
    Crypto::SymmetricKey const& userSecret);

void to_json(nlohmann::json&, VerificationMethod const&) = delete;
void from_json(nlohmann::json const&, VerificationMethod&);

void validateVerification(
    Verification const& verification,
    Identity::SecretProvisionalIdentity const& provisionalIdentity);

inline bool operator<(VerificationMethod const& a, VerificationMethod const& b)
{
  return a._variant < b._variant;
}
}
}
