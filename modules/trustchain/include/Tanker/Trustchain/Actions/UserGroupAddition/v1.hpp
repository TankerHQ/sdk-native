#pragma once

#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>

#include <utility>
#include <vector>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
#define TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_ADDITION1_ATTRIBUTES \
  (groupId, GroupId), (previousGroupBlockHash, Crypto::Hash),     \
      (sealedPrivateEncryptionKeysForUsers, SealedPrivateEncryptionKeysForUsers), (selfSignature, Crypto::Signature)

class UserGroupAddition1
{
public:
  using SealedPrivateEncryptionKeysForUsers =
      std::vector<std::pair<Crypto::PublicEncryptionKey, Crypto::SealedPrivateEncryptionKey>>;

  TANKER_IMMUTABLE_ACTION_IMPLEMENTATION(UserGroupAddition1, TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_ADDITION1_ATTRIBUTES)

public:
  UserGroupAddition1(TrustchainId const& trustchainId,
                     GroupId const& groupId,
                     Crypto::Hash const& previousGroupBlockHash,
                     SealedPrivateEncryptionKeysForUsers const& sealedPrivateEncryptionKeysForUsers,
                     Crypto::Hash const& author,
                     Crypto::PrivateSignatureKey const& groupPrivateSignatureKey,
                     Crypto::PrivateSignatureKey const& devicePrivateSignatureKey);

  std::vector<std::uint8_t> signatureData() const;

private:
  friend void from_serialized(Serialization::SerializedSource&, UserGroupAddition1&);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(UserGroupAddition1)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(UserGroupAddition1)
}
}
}
