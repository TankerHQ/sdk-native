#include <Tanker/Trustchain/Actions/UserGroupCreation/v1.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

#include <stdexcept>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
UserGroupCreation1::UserGroupCreation1(
    Crypto::PublicSignatureKey const& publicSignatureKey,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Crypto::SealedPrivateSignatureKey const& sealedPrivateSignatureKey,
    SealedPrivateEncryptionKeysForUsers const&
        sealedPrivateEncryptionKeysForUsers)
  : _publicSignatureKey(publicSignatureKey),
    _publicEncryptionKey(publicEncryptionKey),
    _sealedPrivateSignatureKey(sealedPrivateSignatureKey),
    _sealedPrivateEncryptionKeysForUsers(sealedPrivateEncryptionKeysForUsers),
    _selfSignature{}
{
}

std::vector<std::uint8_t> UserGroupCreation1::signatureData() const
{
  std::vector<std::uint8_t> signatureData(
      Crypto::PublicSignatureKey::arraySize +
      Crypto::PublicEncryptionKey::arraySize +
      Crypto::SealedPrivateSignatureKey::arraySize +
      (_sealedPrivateEncryptionKeysForUsers.size() *
       (Crypto::PublicEncryptionKey::arraySize +
        Crypto::SealedPrivateEncryptionKey::arraySize)));
  auto it = std::copy(_publicSignatureKey.begin(),
                      _publicSignatureKey.end(),
                      signatureData.begin());
  it = std::copy(_publicEncryptionKey.begin(), _publicEncryptionKey.end(), it);
  it = std::copy(
      _sealedPrivateSignatureKey.begin(), _sealedPrivateSignatureKey.end(), it);
  for (auto const& elem : _sealedPrivateEncryptionKeysForUsers)
  {
    it = std::copy(elem.first.begin(), elem.first.end(), it);
    it = std::copy(elem.second.begin(), elem.second.end(), it);
  }
  return signatureData;
}

Crypto::Signature const& UserGroupCreation1::selfSign(
    Crypto::PrivateSignatureKey const& privateSignatureKey)
{
  auto const toSign = signatureData();

  return _selfSignature = Crypto::sign(toSign, privateSignatureKey);
}

void from_serialized(Serialization::SerializedSource& ss,
                     UserGroupCreation1& ugc)
{
  Serialization::deserialize_to(ss, ugc._publicSignatureKey);
  Serialization::deserialize_to(ss, ugc._publicEncryptionKey);
  Serialization::deserialize_to(ss, ugc._sealedPrivateSignatureKey);
  Serialization::deserialize_to(ss, ugc._sealedPrivateEncryptionKeysForUsers);
  Serialization::deserialize_to(ss, ugc._selfSignature);
}

std::uint8_t* to_serialized(std::uint8_t* it, UserGroupCreation1 const& ugc)
{
  it = Serialization::serialize(it, ugc.publicSignatureKey());
  it = Serialization::serialize(it, ugc.publicEncryptionKey());
  it = Serialization::serialize(it, ugc.sealedPrivateSignatureKey());
  it = Serialization::serialize(it, ugc.sealedPrivateEncryptionKeysForUsers());
  return Serialization::serialize(it, ugc.selfSignature());
}

std::size_t serialized_size(UserGroupCreation1 const& ugc)
{
  return Crypto::PublicSignatureKey::arraySize +
         Crypto::PublicEncryptionKey::arraySize +
         Crypto::SealedPrivateSignatureKey::arraySize +
         Serialization::serialized_size(
             ugc.sealedPrivateEncryptionKeysForUsers()) +
         Crypto::Signature::arraySize;
}

void to_json(nlohmann::json& j, UserGroupCreation1 const& ugc)
{
  j["publicSignatureKey"] = ugc.publicSignatureKey();
  j["publicEncryptionKey"] = ugc.publicEncryptionKey();
  j["sealedPrivateSignatureKey"] = ugc.sealedPrivateSignatureKey();
  j["sealedPrivateEncryptionKeysForUsers"] =
      ugc.sealedPrivateEncryptionKeysForUsers();
  j["selfSignature"] = ugc.selfSignature();
}
}
}
}
