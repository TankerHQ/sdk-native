#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Json.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Serialization.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>
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
      (sealedPrivateEncryptionKeysForUsers,                       \
       SealedPrivateEncryptionKeysForUsers),                      \
      (selfSignature, Crypto::Signature)

class UserGroupAddition1
{
public:
  using SealedPrivateEncryptionKeysForUsers =
      std::vector<std::pair<Crypto::PublicEncryptionKey,
                            Crypto::SealedPrivateEncryptionKey>>;

  TANKER_IMMUTABLE_DATA_TYPE_IMPLEMENTATION_2(
      UserGroupAddition1,
      TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_ADDITION1_ATTRIBUTES)

public:
  UserGroupAddition1(
      TrustchainId const& trustchainId,
      GroupId const& groupId,
      Crypto::Hash const& previousGroupBlockHash,
      SealedPrivateEncryptionKeysForUsers const&
          sealedPrivateEncryptionKeysForUsers,
      Crypto::Hash const& author,
      Crypto::PrivateSignatureKey const& groupPrivateSignatureKey,
      Crypto::PrivateSignatureKey const& devicePrivateSignatureKey);

  static constexpr Nature nature();

  std::vector<std::uint8_t> signatureData() const;

private:
  friend void from_serialized(Serialization::SerializedSource&,
                              UserGroupAddition1&);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(UserGroupAddition1)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(UserGroupAddition1)

constexpr Nature UserGroupAddition1::nature()
{
  return Nature::UserGroupAddition;
}
}
}
}
