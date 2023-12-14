#include <Tanker/Trustchain/Actions/SessionCertificate.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Serialization.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
SessionCertificate::SessionCertificate(TrustchainId const& trustchainId,
                                       Crypto::PublicSignatureKey const& sessionPublicSignatureKey,
                                       uint64_t timestamp,
                                       VerificationMethodType verificationMethodType,
                                       Crypto::Hash const& verificationMethodTarget,
                                       Crypto::Hash const& author,
                                       Crypto::PrivateSignatureKey const& devicePrivateSignatureKey)
  : _trustchainId(trustchainId),
    _sessionPublicSignatureKey(sessionPublicSignatureKey),
    _timestamp(timestamp),
    _verificationMethodType(verificationMethodType),
    _verificationMethodTarget(verificationMethodTarget),
    _author(author),
    _hash(computeHash()),
    _signature(Crypto::sign(_hash, devicePrivateSignatureKey))
{
}

std::vector<std::uint8_t> SessionCertificate::signatureData() const
{
  std::vector<std::uint8_t> signatureData(8 + Crypto::PublicSignatureKey::arraySize +
                                          Serialization::varint_size((uint32_t)_verificationMethodType) +
                                          Crypto::Hash::arraySize);

  auto it = std::copy(_sessionPublicSignatureKey.begin(), _sessionPublicSignatureKey.end(), &*signatureData.begin());
  it = std::copy((char*)_timestamp, (char*)_timestamp + 8, it);
  it = Serialization::varint_write(&*it, (uint32_t)_verificationMethodType);
  std::copy(_verificationMethodTarget.begin(), _verificationMethodTarget.end(), it);
  return signatureData;
}

std::uint8_t* to_serialized(std::uint8_t* it, VerificationMethodType const& mt)
{
  return Serialization::varint_write(it, static_cast<uint32_t>(mt));
}

void from_serialized(Serialization::SerializedSource& ss, VerificationMethodType& mt)
{
  mt = static_cast<VerificationMethodType>(ss.read_varint());
}

TANKER_TRUSTCHAIN_ACTION_DEFINE_METHODS(SessionCertificate, TANKER_TRUSTCHAIN_ACTIONS_SESSION_CERTIFICATE_ATTRIBUTES)
}
}
}
