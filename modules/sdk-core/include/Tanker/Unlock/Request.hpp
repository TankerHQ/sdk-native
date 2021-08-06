#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Trustchain/HashedPassphrase.hpp>
#include <Tanker/Types/BufferWrapper.hpp>
#include <Tanker/Types/EncryptedEmail.hpp>
#include <Tanker/Types/PhoneNumber.hpp>
#include <Tanker/Types/VerificationCode.hpp>
#include <Tanker/Unlock/Verification.hpp>

#include <boost/variant2/variant.hpp>

#include <nlohmann/json_fwd.hpp>

#include <optional>
#include <tuple>
#include <vector>

namespace Tanker::Unlock
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

using RequestVerificationMethods =
    boost::variant2::variant<VerificationKey,
                             EncryptedEmailVerification,
                             Trustchain::HashedPassphrase,
                             OidcIdToken,
                             EncryptedPhoneNumberVerification>;

struct RequestWithVerif
{
  RequestVerificationMethods verification;
  std::optional<std::string> withTokenNonce;
};

void to_json(nlohmann::json&, RequestWithVerif const&);

RequestWithVerif makeRequestWithVerif(
    Unlock::Verification const& verification,
    Crypto::SymmetricKey const& userSecret,
    std::optional<Crypto::SignatureKeyPair> const& secretProvisionalSigKey,
    std::optional<std::string> const& withTokenNonce = std::nullopt);
}

namespace nlohmann
{
template <typename SFINAE>
struct adl_serializer<Tanker::Unlock::RequestVerificationMethods, SFINAE>
{
  static void to_json(
      nlohmann::json& j,
      Tanker::Unlock::RequestVerificationMethods const& request);

  static void from_json(nlohmann::json const& j,
                        Tanker::Unlock::RequestVerificationMethods& request) =
      delete;
};
}
