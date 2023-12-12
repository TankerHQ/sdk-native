#pragma once

#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateSignatureKey.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>

#include <utility>
#include <vector>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
#define TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_CREATION_V1_ATTRIBUTES                                     \
  (publicSignatureKey, Crypto::PublicSignatureKey), (publicEncryptionKey, Crypto::PublicEncryptionKey), \
      (sealedPrivateSignatureKey, Crypto::SealedPrivateSignatureKey),                                   \
      (sealedPrivateEncryptionKeysForUsers, SealedPrivateEncryptionKeysForUsers), (selfSignature, Crypto::Signature)

class UserGroupCreation1
{
public:
  using SealedPrivateEncryptionKeysForUsers =
      std::vector<std::pair<Crypto::PublicEncryptionKey, Crypto::SealedPrivateEncryptionKey>>;

  TANKER_IMMUTABLE_ACTION_IMPLEMENTATION(UserGroupCreation1,
                                         TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_CREATION_V1_ATTRIBUTES)

public:
  UserGroupCreation1(TrustchainId const& trustchainId,
                     Crypto::PublicSignatureKey const& publicSignatureKey,
                     Crypto::PublicEncryptionKey const& publicEncryptionKey,
                     Crypto::SealedPrivateSignatureKey const& sealedPrivateSignatureKey,
                     SealedPrivateEncryptionKeysForUsers const& sealedPrivateEncryptionKeysForUsers,
                     Crypto::Hash const& author,
                     Crypto::PrivateSignatureKey const& groupPrivateSignatureKey,
                     Crypto::PrivateSignatureKey const& devicePrivateSignatureKey);

  std::vector<std::uint8_t> signatureData() const;

private:
  friend void from_serialized(Serialization::SerializedSource&, UserGroupCreation1&);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(UserGroupCreation1)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(UserGroupCreation1)
}
}
}
