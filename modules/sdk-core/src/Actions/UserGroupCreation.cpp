#include <Tanker/Actions/UserGroupCreation.hpp>

#include <Tanker/Actions/UserKeyPair.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Index.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Types/UserId.hpp>

#include <gsl-lite.hpp>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <iterator>
#include <stdexcept>
#include <tuple>

using Tanker::Trustchain::Actions::Nature;

namespace Tanker
{
Nature UserGroupCreation::nature() const
{
  return Nature::UserGroupCreation;
}

std::vector<Index> UserGroupCreation::makeIndexes() const
{
  return {};
}

std::vector<uint8_t> UserGroupCreation::signatureData() const
{
  std::vector<uint8_t> signatureData;
  signatureData.reserve(publicSignatureKey.size() + publicEncryptionKey.size() +
                        encryptedPrivateSignatureKey.size() +
                        Serialization::serialized_size(
                            encryptedGroupPrivateEncryptionKeysForUsers));
  signatureData.insert(signatureData.end(),
                       publicSignatureKey.begin(),
                       publicSignatureKey.end());
  signatureData.insert(signatureData.end(),
                       publicEncryptionKey.begin(),
                       publicEncryptionKey.end());
  signatureData.insert(signatureData.end(),
                       encryptedPrivateSignatureKey.begin(),
                       encryptedPrivateSignatureKey.end());
  for (auto const& elem : encryptedGroupPrivateEncryptionKeysForUsers)
  {
    signatureData.insert(signatureData.end(),
                         elem.publicUserEncryptionKey.begin(),
                         elem.publicUserEncryptionKey.end());
    signatureData.insert(signatureData.end(),
                         elem.encryptedGroupPrivateEncryptionKey.begin(),
                         elem.encryptedGroupPrivateEncryptionKey.end());
  }
  return signatureData;
}

bool operator==(UserGroupCreation const& l, UserGroupCreation const& r)
{
  return std::tie(l.publicSignatureKey,
                  l.publicEncryptionKey,
                  l.encryptedPrivateSignatureKey,
                  l.encryptedGroupPrivateEncryptionKeysForUsers,
                  l.selfSignature) ==
         std::tie(r.publicSignatureKey,
                  r.publicEncryptionKey,
                  r.encryptedPrivateSignatureKey,
                  r.encryptedGroupPrivateEncryptionKeysForUsers,
                  r.selfSignature);
}

bool operator!=(UserGroupCreation const& l, UserGroupCreation const& r)
{
  return !(l == r);
}

UserGroupCreation deserializeUserGroupCreation(gsl::span<uint8_t const> data)
{
  UserGroupCreation out{};

  Serialization::SerializedSource ss{data};

  out.publicSignatureKey =
      Serialization::deserialize<Crypto::PublicSignatureKey>(ss);
  out.publicEncryptionKey =
      Serialization::deserialize<Crypto::PublicEncryptionKey>(ss);
  out.encryptedPrivateSignatureKey =
      Serialization::deserialize<Crypto::SealedPrivateSignatureKey>(ss);
  out.encryptedGroupPrivateEncryptionKeysForUsers =
      Serialization::deserialize<UserGroupCreation::GroupEncryptedKeys>(ss);
  out.selfSignature = Serialization::deserialize<Crypto::Signature>(ss);

  if (!ss.eof())
    throw std::runtime_error("trailing garbage at end of UserGroupCreation");

  return out;
}

std::uint8_t* to_serialized(std::uint8_t* it, UserGroupCreation const& dc)
{
  it = Serialization::serialize(it, dc.publicSignatureKey);
  it = Serialization::serialize(it, dc.publicEncryptionKey);
  it = Serialization::serialize(it, dc.encryptedPrivateSignatureKey);
  it = Serialization::serialize(it,
                                dc.encryptedGroupPrivateEncryptionKeysForUsers);
  return Serialization::serialize(it, dc.selfSignature);
}

std::size_t serialized_size(UserGroupCreation const& dc)
{
  return dc.publicSignatureKey.size() + dc.publicEncryptionKey.size() +
         dc.encryptedPrivateSignatureKey.size() +
         Serialization::serialized_size(
             dc.encryptedGroupPrivateEncryptionKeysForUsers) +
         dc.selfSignature.size();
}

void to_json(nlohmann::json& j, UserGroupCreation const& dc)
{
  j["publicSignatureKey"] = dc.publicSignatureKey;
  j["publicEncryptionKey"] = dc.publicEncryptionKey;
  j["encryptedPrivateSignatureKey"] = dc.encryptedPrivateSignatureKey;
  j["encryptedGroupPrivateEncryptionKeysForUsers"] =
      dc.encryptedGroupPrivateEncryptionKeysForUsers;
  j["selfSignature"] = dc.selfSignature;
}
}
