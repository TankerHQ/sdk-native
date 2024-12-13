#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/VariantImplementation.hpp>
#include <Tanker/Types/E2ePassphrase.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/EncryptedEmail.hpp>
#include <Tanker/Types/EncryptedPhoneNumber.hpp>
#include <Tanker/Types/EncryptedPreverifiedEmail.hpp>
#include <Tanker/Types/EncryptedPreverifiedPhoneNumber.hpp>
#include <Tanker/Types/OidcAuthorizationCode.hpp>
#include <Tanker/Types/OidcIdToken.hpp>
#include <Tanker/Types/OidcNonce.hpp>
#include <Tanker/Types/Passphrase.hpp>
#include <Tanker/Types/PhoneNumber.hpp>
#include <Tanker/Types/PrehashedAndEncryptedPassphrase.hpp>
#include <Tanker/Types/PreverifiedEmail.hpp>
#include <Tanker/Types/PreverifiedOidc.hpp>
#include <Tanker/Types/PreverifiedPhoneNumber.hpp>
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
struct ByEmail
{
  Email email;
  VerificationCode verificationCode;
};

struct ByPhoneNumber
{
  PhoneNumber phoneNumber;
  VerificationCode verificationCode;
};

using Verification = boost::variant2::variant<VerificationKey,
                                              ByEmail,
                                              Passphrase,
                                              E2ePassphrase,
                                              OidcIdToken,
                                              ByPhoneNumber,
                                              PreverifiedEmail,
                                              PreverifiedPhoneNumber,
                                              PreverifiedOidc,
                                              OidcAuthorizationCode,
                                              PrehashedAndEncryptedPassphrase>;

class VerificationMethod
{
  TANKER_TRUSTCHAIN_ACTION_VARIANT_IMPLEMENTATION_ZERO(VerificationMethod,
                                                       (VerificationKey,
                                                        Email,
                                                        Passphrase,
                                                        E2ePassphrase,
                                                        OidcIdToken,
                                                        PhoneNumber,
                                                        PreverifiedEmail,
                                                        PreverifiedPhoneNumber,
                                                        PreverifiedOidc,
                                                        OidcAuthorizationCode,
                                                        PrehashedAndEncryptedPassphrase))

  static VerificationMethod from(Verification const& v);

private:
  friend bool operator<(VerificationMethod const& a, VerificationMethod const& b);
};

class EncryptedVerificationMethod
{
  TANKER_TRUSTCHAIN_ACTION_VARIANT_IMPLEMENTATION_ZERO(
      EncryptedVerificationMethod,
      (EncryptedEmail, EncryptedPhoneNumber, EncryptedPreverifiedEmail, EncryptedPreverifiedPhoneNumber))

private:
  friend bool operator<(EncryptedVerificationMethod const& a, EncryptedVerificationMethod const& b);
};

tc::cotask<std::vector<VerificationMethod>> decryptMethods(
    std::vector<boost::variant2::variant<VerificationMethod, EncryptedVerificationMethod>>& methods,
    Crypto::SymmetricKey const& userSecret);

void to_json(nlohmann::json&,
             boost::variant2::variant<VerificationMethod, EncryptedVerificationMethod> const&) = delete;
void from_json(nlohmann::json const&, boost::variant2::variant<VerificationMethod, EncryptedVerificationMethod>&);

void validateVerification(Verification const& verification,
                          Identity::SecretProvisionalIdentity const& provisionalIdentity);

bool isPreverified(Verification const& v);

bool isE2eVerification(Verification const& v);

inline bool operator<(VerificationMethod const& a, VerificationMethod const& b)
{
  return a._variant < b._variant;
}
}
}
