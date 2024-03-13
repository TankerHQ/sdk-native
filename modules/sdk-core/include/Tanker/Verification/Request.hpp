#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Identity/TargetType.hpp>
#include <Tanker/Trustchain/HashedE2ePassphrase.hpp>
#include <Tanker/Trustchain/HashedPassphrase.hpp>
#include <Tanker/Types/BufferWrapper.hpp>
#include <Tanker/Types/EncryptedEmail.hpp>
#include <Tanker/Types/EncryptedVerificationKeyForE2ePassphrase.hpp>
#include <Tanker/Types/EncryptedVerificationKeyForUserKey.hpp>
#include <Tanker/Types/EncryptedVerificationKeyForUserSecret.hpp>
#include <Tanker/Types/OidcChallenge.hpp>
#include <Tanker/Types/PhoneNumber.hpp>
#include <Tanker/Types/VerificationCode.hpp>
#include <Tanker/Verification/Verification.hpp>

#include <boost/variant2/variant.hpp>

#include <nlohmann/json_fwd.hpp>

#include <optional>
#include <tuple>
#include <vector>

namespace Tanker::Verification
{
struct EncryptedEmailVerification
{
  Crypto::Hash hashedEmail;
  EncryptedEmail encryptedEmail;
  VerificationCode verificationCode;
};

struct EncryptedPhoneNumberVerification
{
  PhoneNumber phoneNumber;
  Crypto::Hash userSalt;
  std::optional<Crypto::Hash> provisionalSalt;
  EncryptedPhoneNumber encryptedPhoneNumber;
  VerificationCode verificationCode;
};

struct EncryptedPreverifiedEmailVerification
{
  Crypto::Hash hashedEmail;
  EncryptedEmail encryptedEmail;
};

struct EncryptedPreverifiedPhoneNumberVerification
{
  PhoneNumber phoneNumber;
  Crypto::Hash userSalt;
  std::optional<Crypto::Hash> provisionalSalt;
  EncryptedPhoneNumber encryptedPhoneNumber;
};

struct OidcIdTokenWithChallenge
{
  OidcIdToken oidcIdToken;
  Oidc::SignedChallenge oidcChallenge;
  std::optional<Oidc::Nonce> oidcTestNonce;
};

using RequestVerification = boost::variant2::variant<VerificationKey,
                                                     ByEmail,
                                                     Passphrase,
                                                     E2ePassphrase,
                                                     OidcIdTokenWithChallenge,
                                                     ByPhoneNumber,
                                                     PreverifiedEmail,
                                                     PreverifiedPhoneNumber,
                                                     PreverifiedOidc,
                                                     OidcAuthorizationCode>;

using RequestVerificationPayload = boost::variant2::variant<VerificationKey,
                                                            EncryptedEmailVerification,
                                                            Trustchain::HashedPassphrase,
                                                            Trustchain::HashedE2ePassphrase,
                                                            OidcIdToken,
                                                            OidcIdTokenWithChallenge,
                                                            EncryptedPhoneNumberVerification,
                                                            EncryptedPreverifiedEmailVerification,
                                                            EncryptedPreverifiedPhoneNumberVerification,
                                                            PreverifiedOidc,
                                                            OidcAuthorizationCode>;

struct RequestWithVerif
{
  RequestVerificationPayload verification;
  std::optional<std::string> withTokenNonce;
};

void to_json(nlohmann::json&, RequestWithVerif const&);

struct SetVerifMethodRequest
{
  RequestWithVerif verification;
  std::optional<EncryptedVerificationKeyForUserSecret> encVkForUserSecret;
  std::optional<EncryptedVerificationKeyForUserKey> encVkForUserKey;
  std::optional<EncryptedVerificationKeyForE2ePassphrase> encVkForE2ePass;
};

void to_json(nlohmann::json&, SetVerifMethodRequest const&);

RequestWithVerif makeRequestWithVerif(RequestVerification const& verification,
                                      Crypto::SymmetricKey const& userSecret,
                                      std::optional<Crypto::SignatureKeyPair> const& secretProvisionalSigKey,
                                      std::optional<std::string> const& withTokenNonce = std::nullopt);

RequestWithVerif makeRequestWithVerif(Verification const& verification,
                                      Crypto::SymmetricKey const& userSecret,
                                      std::optional<Crypto::SignatureKeyPair> const& secretProvisionalSigKey,
                                      std::optional<std::string> const& withTokenNonce = std::nullopt);

std::vector<RequestWithVerif> makeRequestWithVerifs(std::vector<Verification> const& verification,
                                                    Crypto::SymmetricKey const& userSecret);

struct EmailSessionRequest
{
  Email email;
};

struct PhoneNumberSessionRequest
{
  PhoneNumber phoneNumber;
  Crypto::Hash userSalt;
  Crypto::Hash provisionalSalt;
};

using SessionRequestValue = boost::variant2::variant<EmailSessionRequest, PhoneNumberSessionRequest>;

struct RequestWithSession
{
  Identity::TargetType target;
  SessionRequestValue value;
};

void to_json(nlohmann::json&, RequestWithSession const&);

RequestWithSession makeRequestWithSession(Identity::SecretProvisionalIdentity const& identity,
                                          Crypto::SymmetricKey const& userSecret);
}

namespace nlohmann
{
template <typename SFINAE>
struct adl_serializer<Tanker::Verification::RequestVerificationPayload, SFINAE>
{
  static void to_json(nlohmann::json& j, Tanker::Verification::RequestVerificationPayload const& request);

  static void from_json(nlohmann::json const& j, Tanker::Verification::RequestVerificationPayload& request) = delete;
};

template <typename SFINAE>
struct adl_serializer<Tanker::Verification::SessionRequestValue, SFINAE>
{
  static void to_json(nlohmann::json& j, Tanker::Verification::SessionRequestValue const& request);

  static void from_json(nlohmann::json const& j, Tanker::Verification::SessionRequestValue& request) = delete;
};
}
