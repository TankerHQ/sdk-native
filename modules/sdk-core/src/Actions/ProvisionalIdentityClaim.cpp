#include <Tanker/Actions/ProvisionalIdentityClaim.hpp>

#include <Tanker/Index.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <gsl-lite.hpp>
#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

using Tanker::Trustchain::Actions::Nature;

namespace Tanker
{
Nature ProvisionalIdentityClaim::nature() const
{
  return Nature::ProvisionalIdentityClaim;
}

std::vector<Index> ProvisionalIdentityClaim::makeIndexes() const
{
  return {};
}

std::vector<uint8_t> ProvisionalIdentityClaim::signatureData(
    Trustchain::DeviceId const& authorId) const
{
  std::vector<uint8_t> signatureData;
  signatureData.reserve(authorId.size() + appSignaturePublicKey.size() +
                        tankerSignaturePublicKey.size());
  signatureData.insert(signatureData.end(), authorId.begin(), authorId.end());
  signatureData.insert(signatureData.end(),
                       appSignaturePublicKey.begin(),
                       appSignaturePublicKey.end());
  signatureData.insert(signatureData.end(),
                       tankerSignaturePublicKey.begin(),
                       tankerSignaturePublicKey.end());
  return signatureData;
}

bool operator==(ProvisionalIdentityClaim const& l,
                ProvisionalIdentityClaim const& r)
{
  return std::tie(l.userId,
                  l.appSignaturePublicKey,
                  l.tankerSignaturePublicKey,
                  l.authorSignatureByAppKey,
                  l.authorSignatureByTankerKey,
                  l.userPublicEncryptionKey,
                  l.encryptedPrivateKeys) ==
         std::tie(r.userId,
                  r.appSignaturePublicKey,
                  r.tankerSignaturePublicKey,
                  r.authorSignatureByAppKey,
                  r.authorSignatureByTankerKey,
                  r.userPublicEncryptionKey,
                  r.encryptedPrivateKeys);
}

bool operator!=(ProvisionalIdentityClaim const& l,
                ProvisionalIdentityClaim const& r)
{
  return !(l == r);
}

std::size_t serialized_size(ProvisionalIdentityClaim const& dc)
{
  return Trustchain::UserId::arraySize + Crypto::PublicSignatureKey::arraySize +
         Crypto::PublicSignatureKey::arraySize + Crypto::Signature::arraySize +
         Crypto::Signature::arraySize + Crypto::PublicEncryptionKey::arraySize +
         ProvisionalIdentityClaim::SealedPrivateEncryptionKeys::arraySize;
}

std::uint8_t* to_serialized(std::uint8_t* it,
                            ProvisionalIdentityClaim const& pic)
{
  it = Serialization::serialize(it, pic.userId);
  it = Serialization::serialize(it, pic.appSignaturePublicKey);
  it = Serialization::serialize(it, pic.tankerSignaturePublicKey);
  it = Serialization::serialize(it, pic.authorSignatureByAppKey);
  it = Serialization::serialize(it, pic.authorSignatureByTankerKey);
  it = Serialization::serialize(it, pic.userPublicEncryptionKey);
  it = Serialization::serialize(it, pic.encryptedPrivateKeys);
  return it;
}

ProvisionalIdentityClaim deserializeProvisionalIdentityClaim(
    gsl::span<uint8_t const> data)
{
  ProvisionalIdentityClaim out;
  Serialization::SerializedSource ss{data};

  Serialization::deserialize_to(ss, out.userId);
  Serialization::deserialize_to(ss, out.appSignaturePublicKey);
  Serialization::deserialize_to(ss, out.tankerSignaturePublicKey);
  Serialization::deserialize_to(ss, out.authorSignatureByAppKey);
  Serialization::deserialize_to(ss, out.authorSignatureByTankerKey);
  Serialization::deserialize_to(ss, out.userPublicEncryptionKey);
  Serialization::deserialize_to(ss, out.encryptedPrivateKeys);

  if (!ss.eof())
    throw std::runtime_error(
        "trailing garbage at end of ProvisionalIdentityClaim");

  return out;
}

void to_json(nlohmann::json& j, ProvisionalIdentityClaim const& pic)
{
  j["userId"] = pic.userId;
  j["appSignaturePublicKey"] = pic.appSignaturePublicKey;
  j["tankerSignaturePublicKey"] = pic.tankerSignaturePublicKey;
  j["authorSignatureByAppKey"] = pic.authorSignatureByAppKey;
  j["authorSignatureByTankerKey"] = pic.authorSignatureByTankerKey;
  j["userPublicEncryptionKey"] = pic.userPublicEncryptionKey;
  j["encryptedPrivateKeys"] = pic.encryptedPrivateKeys;
}
}
