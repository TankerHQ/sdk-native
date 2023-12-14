#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>
#include <Tanker/Crypto/PrivateEncryptionKey.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateSignatureKey.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Crypto/TwoTimesSealedPrivateEncryptionKey.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <tuple>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
enum class VerificationMethodType : uint32_t
{
  Email = 1,
  Passphrase = 2,
  VerificationKey = 3,
  OidcIdToken = 4,
  PhoneNumber = 5,
  E2ePassphrase = 6,
};

std::uint8_t* to_serialized(std::uint8_t* it, VerificationMethodType const& mt);
void from_serialized(Serialization::SerializedSource& ss, VerificationMethodType& mt);
constexpr std::size_t serialized_size(VerificationMethodType const& mt)
{
  return Serialization::varint_size(static_cast<uint32_t>(mt));
}

#define TANKER_TRUSTCHAIN_ACTIONS_SESSION_CERTIFICATE_ATTRIBUTES                  \
  (sessionPublicSignatureKey, Crypto::PublicSignatureKey), (timestamp, uint64_t), \
      (verificationMethodType, VerificationMethodType), (verificationMethodTarget, Crypto::Hash)

class SessionCertificate
{
public:
  TANKER_IMMUTABLE_ACTION_IMPLEMENTATION(SessionCertificate, TANKER_TRUSTCHAIN_ACTIONS_SESSION_CERTIFICATE_ATTRIBUTES)

public:
  SessionCertificate(TrustchainId const& trustchainId,
                     Crypto::PublicSignatureKey const& sessionPublicSignatureKey,
                     uint64_t timestamp,
                     VerificationMethodType verificationMethodType,
                     Crypto::Hash const& verificationMethodTarget,
                     Crypto::Hash const& author,
                     Crypto::PrivateSignatureKey const& devicePrivateSignatureKey);

  std::vector<std::uint8_t> signatureData() const;

private:
  friend void from_serialized(Serialization::SerializedSource&, SessionCertificate&);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(SessionCertificate)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(SessionCertificate)
}
}
}
